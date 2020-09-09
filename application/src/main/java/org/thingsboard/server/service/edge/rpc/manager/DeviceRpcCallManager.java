/**
 * Copyright © 2016-2020 The Thingsboard Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.thingsboard.server.service.edge.rpc.manager;

import com.datastax.driver.core.utils.UUIDs;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.thingsboard.rule.engine.api.RpcError;
import org.thingsboard.server.common.data.DataConstants;
import org.thingsboard.server.common.data.Device;
import org.thingsboard.server.common.data.id.DeviceId;
import org.thingsboard.server.common.data.id.TenantId;
import org.thingsboard.server.common.msg.TbMsg;
import org.thingsboard.server.common.msg.TbMsgDataType;
import org.thingsboard.server.common.msg.TbMsgMetaData;
import org.thingsboard.server.dao.device.DeviceService;
import org.thingsboard.server.gen.edge.RpcCallMsg;
import org.thingsboard.server.gen.edge.RpcRequestMsg;
import org.thingsboard.server.gen.edge.RpcResponseMsg;
import org.thingsboard.server.queue.TbQueueCallback;
import org.thingsboard.server.queue.TbQueueMsgMetadata;
import org.thingsboard.server.service.queue.TbClusterService;
import org.thingsboard.server.service.rpc.FromDeviceRpcResponse;

import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

@Slf4j
@Component
public class DeviceRpcCallManager {

    private static final Random random = new Random();
    private static final ObjectMapper mapper = new ObjectMapper();

    private final List<String> incomingRequestUUIDs = new CopyOnWriteArrayList();
    private final List<String> fromRuleEngineRequestUUIDs = new CopyOnWriteArrayList<>();

    @Autowired
    private TbClusterService tbClusterService;

    @Autowired
    private DeviceService deviceService;


    public RpcCallMsg processRpcCallMsg(UUID entityId, JsonNode entityBody) {
        try {
            JsonNode data = entityBody.get("data");
            JsonNode metadata = entityBody.get("metadata");
            JsonNode requestUUID = metadata.get("requestUUID");
            RpcCallMsg.Builder builder = RpcCallMsg.newBuilder();
            if (requestUUID == null || !incomingRequestUUIDs.remove(requestUUID.asText())) {
                if (requestUUID == null) {
                    String createdRequestUUID = UUIDs.timeBased().toString();
                    ((ObjectNode) metadata).put("requestUUID", createdRequestUUID);
                    fromRuleEngineRequestUUIDs.add(createdRequestUUID);
                }
                RpcRequestMsg rpcRequestMsg = constructRpcRequestMsg(data);
                builder.setRequestMsg(rpcRequestMsg);
            } else {
                RpcResponseMsg rpcResponseMsg = constructRpcResponseMsg(data);
                builder.setResponseMsg(rpcResponseMsg);
            }
            builder.setDeviceIdMSB(entityId.getMostSignificantBits())
                    .setDeviceIdLBS(entityId.getLeastSignificantBits())
                    .setRequestUUID(metadata.get("requestUUID").asText())
                    .setRequestId(metadata.has("requestId") ? metadata.get("requestId").asInt() : random.nextInt())
                    .setOneway(metadata.has("oneway") ? metadata.get("oneway").asBoolean() : true);
            if (metadata.has("originServiceId")) {
                builder.setOriginServiceId(metadata.get("originServiceId").asText());
            }
            if (metadata.has("expirationTime")) {
                builder.setExpirationTime(metadata.get("expirationTime").asText());
            }
            return builder.build();
        } catch (Exception e) {
            log.error("Can't send rpc call msg, body [{}]", entityBody, e);
            return null;
        }
    }

    public ListenableFuture<Void> processRpcCallMsg(TenantId tenantId, RpcCallMsg rpcCallMsg) {
        ListenableFuture<Void> result = null;
        if (rpcCallMsg.hasRequestMsg()) {
            result = processRpcRequestMsg(tenantId, rpcCallMsg);
        }
        if (rpcCallMsg.hasResponseMsg()) {
            result = processRpcResponseMsg(tenantId, rpcCallMsg);
        }
        return result;
    }

    public ListenableFuture<Void> processRpcResponseMsg(TenantId tenantId, RpcCallMsg rpcCallMsg) {
        log.info("process Rpc Response {}", rpcCallMsg);
        SettableFuture<Void> futureToSet = SettableFuture.create();
        UUID requestUUID = UUID.fromString(rpcCallMsg.getRequestUUID());
        RpcResponseMsg rpcResponseMsg = rpcCallMsg.getResponseMsg();
        TbQueueCallback callback = new TbQueueCallback() {
            @Override
            public void onSuccess(TbQueueMsgMetadata metadata) {
                futureToSet.set(null);
            }

            @Override
            public void onFailure(Throwable t) {
                log.error("Can't process rpc response msg [{}]", rpcCallMsg, t);
                futureToSet.setException(t);
            }
        };
        if (!fromRuleEngineRequestUUIDs.remove(rpcCallMsg.getRequestUUID())) {
            String response = !rpcResponseMsg.getResponse().equals("{}") ? rpcResponseMsg.getResponse() : null;
            RpcError error = !StringUtils.isEmpty(rpcResponseMsg.getError()) ? RpcError.valueOf(rpcResponseMsg.getError()) : null;
            String originServiceId = rpcCallMsg.getOriginServiceId();
            FromDeviceRpcResponse fromDeviceRpcResponse = new FromDeviceRpcResponse(requestUUID, response, error);
            tbClusterService.pushNotificationToCore(originServiceId, fromDeviceRpcResponse, callback);
        } else {
            DeviceId deviceId = new DeviceId(new UUID(rpcCallMsg.getDeviceIdMSB(), rpcCallMsg.getDeviceIdLBS()));
            String data;
            if (!StringUtils.isEmpty(rpcResponseMsg.getError())) {
                ObjectNode dataNode = mapper.createObjectNode();
                dataNode.put("error", rpcResponseMsg.getError());
                data = dataNode.toString();
            } else {
                data = rpcResponseMsg.getResponse();
            }
            TbMsg tbMsg = constructTbMsg(tenantId, deviceId, requestUUID.toString(), DataConstants.RPC_RESPONSE_FROM_EDGE, rpcCallMsg, data);
            tbClusterService.pushMsgToRuleEngine(tenantId, deviceId, tbMsg, callback);
        }
        return futureToSet;
    }

    public ListenableFuture<Void> processRpcRequestMsg(TenantId tenantId, RpcCallMsg rpcCallMsg) {
        SettableFuture<Void> futureToSet = SettableFuture.create();
        DeviceId deviceId = new DeviceId(new UUID(rpcCallMsg.getDeviceIdMSB(), rpcCallMsg.getDeviceIdLBS()));
        String requestUUID = rpcCallMsg.getRequestUUID();
        RpcRequestMsg rpcRequestMsg = rpcCallMsg.getRequestMsg();
        ObjectNode dataNode = mapper.createObjectNode();
        dataNode.put("method", rpcRequestMsg.getMethod());
        dataNode.put("params", rpcRequestMsg.getParams());
        String data = dataNode.toString();
        TbMsg tbMsg = constructTbMsg(tenantId, deviceId, requestUUID, DataConstants.RPC_REQUEST_FROM_EDGE_TO_DEVICE, rpcCallMsg, data);
        incomingRequestUUIDs.add(requestUUID);
        tbClusterService.pushMsgToRuleEngine(tenantId, deviceId, tbMsg, new TbQueueCallback() {
            @Override
            public void onSuccess(TbQueueMsgMetadata metadata) {
                    futureToSet.set(null);
                }

            @Override
            public void onFailure(Throwable t) {
                log.error("Can't process rpc request msg [{}]", rpcCallMsg, t);
                futureToSet.setException(t);
            }
        });
        return futureToSet;
    }

    private RpcResponseMsg constructRpcResponseMsg(JsonNode data) {
        RpcResponseMsg.Builder builder = RpcResponseMsg.newBuilder();
        if (data.has("error")) {
            builder.setError(data.get("error").asText());
        } else {
            builder.setResponse(data.toString());
        }
        return builder.build();
    }

    private RpcRequestMsg constructRpcRequestMsg(JsonNode data) {
        return RpcRequestMsg.newBuilder()
                .setMethod(data.get("method").asText())
                .setParams(data.get("params").asText())
                .build();
    }

    private TbMsg constructTbMsg(TenantId tenantId, DeviceId deviceId, String requestUUID, String type, RpcCallMsg rpcCallMsg, String data) {
        TbMsgMetaData metaData = new TbMsgMetaData();
        metaData.putValue("requestUUID", requestUUID);
        metaData.putValue("originServiceId", rpcCallMsg.getOriginServiceId());
        metaData.putValue("expirationTime", rpcCallMsg.getExpirationTime());
        metaData.putValue("oneway", Boolean.toString(rpcCallMsg.getOneway()));
        Device device = deviceService.findDeviceById(tenantId, deviceId);
        if (device != null) {
            metaData.putValue("deviceName", device.getName());
            metaData.putValue("deviceType", device.getType());
        }
        return TbMsg.newMsg(type, deviceId, metaData, TbMsgDataType.JSON, data);
    }

}
