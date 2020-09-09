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
import com.fasterxml.jackson.core.JsonProcessingException;
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
import org.thingsboard.server.common.data.id.EntityId;
import org.thingsboard.server.common.data.id.TenantId;
import org.thingsboard.server.common.msg.TbMsg;
import org.thingsboard.server.common.msg.TbMsgDataType;
import org.thingsboard.server.common.msg.TbMsgMetaData;
import org.thingsboard.server.dao.device.DeviceService;
import org.thingsboard.server.gen.edge.DownlinkMsg;
import org.thingsboard.server.gen.edge.RpcRequestMsg;
import org.thingsboard.server.gen.edge.RpcResponseMsg;
import org.thingsboard.server.queue.TbQueueCallback;
import org.thingsboard.server.queue.TbQueueMsgMetadata;
import org.thingsboard.server.service.queue.TbClusterService;
import org.thingsboard.server.service.rpc.FromDeviceRpcResponse;

import java.util.Collections;
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


    public DownlinkMsg processRpcCallMsg(UUID entityId, JsonNode entityBody) {
        try {
            JsonNode data = entityBody.get("data");
            JsonNode metadata = entityBody.get("metadata");
            JsonNode requestUUID = metadata.get("requestUUID");
            DownlinkMsg.Builder builder = DownlinkMsg.newBuilder();
            if (requestUUID == null || !incomingRequestUUIDs.remove(requestUUID.asText())) {
                if (requestUUID == null) {
                    String createdRequestUUID = UUIDs.timeBased().toString();
                    ((ObjectNode) metadata).put("requestUUID", createdRequestUUID);
                    fromRuleEngineRequestUUIDs.add(createdRequestUUID);
                }
                RpcRequestMsg rpcRequestMsg = constructRpcRequestMsg(new DeviceId(entityId), data, metadata);
                builder.addAllRpcRequestMsg(Collections.singletonList(rpcRequestMsg));
            } else {
                RpcResponseMsg rpcResponseMsg = constructRpcResponseMsg(data, metadata);
                builder.addAllRpcResponseMsg(Collections.singletonList(rpcResponseMsg));
            }
            return builder.build();
        } catch (Exception e) {
            log.warn("Can't send rpc call msg, body [{}]", entityBody, e);
            return null;
        }
    }

    public ListenableFuture<Void> processRpcResponseMsg(RpcResponseMsg responseMsg) {
        log.info("process Rpc Response {}", responseMsg);
        SettableFuture<Void> futureToSet = SettableFuture.create();
        String originServiceId = responseMsg.getOriginServiceId();
        UUID requestUUID = UUID.fromString(responseMsg.getRequestUUID());
        String response = !responseMsg.getResponse().equals("{}") ? responseMsg.getResponse() : null;
        RpcError error = !StringUtils.isEmpty(responseMsg.getError()) ? RpcError.valueOf(responseMsg.getError()) : null;
        FromDeviceRpcResponse fromDeviceRpcResponse = new FromDeviceRpcResponse(requestUUID, response, error);
        if (!fromRuleEngineRequestUUIDs.remove(responseMsg.getRequestUUID())) {
            log.info("push msg to core");
            tbClusterService.pushNotificationToCore(originServiceId, fromDeviceRpcResponse, new TbQueueCallback() {
                @Override
                public void onSuccess(TbQueueMsgMetadata metadata) {
                    futureToSet.set(null);
                }

                @Override
                public void onFailure(Throwable t) {
                    log.error("Can't process rpc response msg [{}]", responseMsg, t);
                    futureToSet.setException(t);
                }
            });
        } else {
            log.info("push msg to rule engine");
            futureToSet.set(null);
            // push msg to rule engine
        }
        return futureToSet;
    }

    public ListenableFuture<Void> processRpcRequestMsg(TenantId tenantId, RpcRequestMsg rpcRequestMsg) {
        log.info("process Rpc Request {}", rpcRequestMsg);
        SettableFuture<Void> futureToSet = SettableFuture.create();
        TbMsgMetaData metaData = new TbMsgMetaData();
        metaData.putValue("requestUUID", rpcRequestMsg.getRequestUUID());
        metaData.putValue("originServiceId", rpcRequestMsg.getOriginServiceId());
        metaData.putValue("expirationTime", rpcRequestMsg.getExpirationTime());
        metaData.putValue("oneway", Boolean.toString(rpcRequestMsg.getOneway()));
        DeviceId deviceId = new DeviceId(new UUID(rpcRequestMsg.getDeviceIdMSB(), rpcRequestMsg.getDeviceIdLBS()));
        Device device = deviceService.findDeviceById(tenantId, deviceId);
        if (device != null) {
            metaData.putValue("deviceName", device.getName());
            metaData.putValue("deviceType", device.getType());
        }
        ObjectNode entityNode = mapper.createObjectNode();
        entityNode.put("method", rpcRequestMsg.getMethod());
        entityNode.put("params", rpcRequestMsg.getParams());
        try {
            TbMsg tbMsg = TbMsg.newMsg(DataConstants.RPC_CALL_FROM_EDGE_TO_DEVICE, deviceId, metaData, TbMsgDataType.JSON, mapper.writeValueAsString(entityNode));
            incomingRequestUUIDs.add(metaData.getValue("requestUUID"));
            tbClusterService.pushMsgToRuleEngine(tenantId, deviceId, tbMsg, new TbQueueCallback() {
                @Override
                public void onSuccess(TbQueueMsgMetadata metadata) {
                    futureToSet.set(null);
                }

                @Override
                public void onFailure(Throwable t) {
                    log.error("Can't process rpc request msg [{}]", rpcRequestMsg, t);
                    futureToSet.setException(t);
                }
            });
        } catch (JsonProcessingException e) {
            log.error("Error during processing rpc request msg", e);
            futureToSet.setException(e);
        }
        return futureToSet;
    }

    private RpcResponseMsg constructRpcResponseMsg(JsonNode data, JsonNode metadata) {
        log.info("Construct rpc response");
        RpcResponseMsg.Builder builder = RpcResponseMsg.newBuilder()
                .setOriginServiceId(metadata.get("originServiceId").asText())
                .setRequestUUID(metadata.get("requestUUID").asText());
        if (data.has("error")) {
            builder.setError(data.get("error").asText());
        } else {
            builder.setResponse(data.toString());
        }
        return builder.build();
    }

    private RpcRequestMsg constructRpcRequestMsg(EntityId entityId, JsonNode data, JsonNode metadata) {
        log.info("construct Rpc request");
        RpcRequestMsg.Builder builder = RpcRequestMsg.newBuilder()
                .setDeviceIdMSB(entityId.getId().getMostSignificantBits())
                .setDeviceIdLBS(entityId.getId().getLeastSignificantBits())
                .setMethod(data.get("method").asText())
                .setParams(data.get("params").asText())
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
    }

}
