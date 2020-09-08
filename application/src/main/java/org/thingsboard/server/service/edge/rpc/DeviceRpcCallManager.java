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
package org.thingsboard.server.service.edge.rpc;

import com.datastax.driver.core.utils.UUIDs;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
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

    private final List<String> requestUUIDs = new CopyOnWriteArrayList();

    @Autowired
    private TbClusterService tbClusterService;

    @Autowired
    private DeviceService deviceService;


    public DownlinkMsg processRpcCallMsg(UUID entityId, JsonNode entityBody) {
        try {
            JsonNode requestUUID = entityBody.get("metadata").get("requestUUID");
            if (requestUUID == null || !requestUUIDs.remove(requestUUID.asText())) {
                RpcRequestMsg rpcRequestMsg = constructRpcRequestMsg(new DeviceId(entityId), entityBody);
                DownlinkMsg.Builder builder = DownlinkMsg.newBuilder()
                        .addAllRpcRequestMsg(Collections.singletonList(rpcRequestMsg));
                log.info(String.valueOf(rpcRequestMsg));
                return builder.build();
            } else {
                RpcResponseMsg rpcResponseMsg = constructRpcResponseMsg(entityBody);
                DownlinkMsg.Builder builder = DownlinkMsg.newBuilder()
                        .addAllRpcResponseMsg(Collections.singletonList(rpcResponseMsg));
                log.info(String.valueOf(rpcResponseMsg));
                return builder.build();
            }
        } catch (Exception e) {
            log.warn("Can't send rpc response msg, body [{}]", entityBody, e);
            return null;
        }
    }

    public ListenableFuture<Void> processRpcResponseMsg(RpcResponseMsg responseMsg) {
        SettableFuture<Void> futureToSet = SettableFuture.create();
        String originServiceId = responseMsg.getOriginServiceId();
        UUID requestUUID = UUID.fromString(responseMsg.getRequestUUID());
        String response = responseMsg.getResponse();
        FromDeviceRpcResponse fromDeviceRpcResponse = new FromDeviceRpcResponse(requestUUID, response, null);
        log.info(String.valueOf(fromDeviceRpcResponse));
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
        log.info(String.valueOf(responseMsg));
        return futureToSet;
    }

    public ListenableFuture<Void> processRpcRequestMsg(TenantId tenantId, RpcRequestMsg rpcRequestMsg) {
        SettableFuture<Void> futureToSet = SettableFuture.create();
        ObjectNode entityNode = mapper.createObjectNode();
        TbMsgMetaData metaData = new TbMsgMetaData();
        metaData.putValue("requestUUID", rpcRequestMsg.getRequestUUID());
        metaData.putValue("originServiceId", rpcRequestMsg.getOriginServiceId());
        metaData.putValue("expirationTime", Long.toString(rpcRequestMsg.getExpirationTime()));
        metaData.putValue("oneway", Boolean.toString(rpcRequestMsg.getOneway()));
        Device device = deviceService.findDeviceById(tenantId, new DeviceId(new UUID(rpcRequestMsg.getDeviceIdMSB(), rpcRequestMsg.getDeviceIdLBS())));
        if (device != null) {
            metaData.putValue("deviceName", device.getName());
            metaData.putValue("deviceType", device.getType());
        }
        entityNode.put("method", rpcRequestMsg.getMethod());
        entityNode.put("params", rpcRequestMsg.getParams());
        try {
            DeviceId deviceId = new DeviceId(new UUID(rpcRequestMsg.getDeviceIdMSB(), rpcRequestMsg.getDeviceIdLBS()));
            TbMsg tbMsg = TbMsg.newMsg(DataConstants.RPC_CALL_FROM_EDGE_TO_DEVICE, deviceId, metaData, TbMsgDataType.JSON, mapper.writeValueAsString(entityNode));
            requestUUIDs.add(metaData.getValue("requestUUID"));
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
        log.info(String.valueOf(rpcRequestMsg));
        return futureToSet;
    }

    private RpcResponseMsg constructRpcResponseMsg(JsonNode entityData) {
        RpcResponseMsg rpcResponseMsg = RpcResponseMsg.newBuilder()
                .setResponse(entityData.get("data").toString())
                .setOriginServiceId(entityData.get("metadata").get("originServiceId").asText())
                .setRequestUUID(entityData.get("metadata").get("requestUUID").asText())
                .build();
        return rpcResponseMsg;
    }

    private RpcRequestMsg constructRpcRequestMsg(EntityId entityId, JsonNode entityBody) {
        log.info(String.valueOf(entityBody));
        RpcRequestMsg.Builder builder = RpcRequestMsg.newBuilder()
                .setDeviceIdMSB(entityId.getId().getMostSignificantBits())
                .setDeviceIdLBS(entityId.getId().getLeastSignificantBits());
        JsonNode data = entityBody.get("data");
        builder.setMethod(data.get("method").asText());
        builder.setParams(data.get("params").asText());
        JsonNode metadata = entityBody.get("metadata");
        builder.setRequestId(metadata.has("requestId") ? metadata.get("requestId").asInt() : random.nextInt());
        builder.setRequestUUID(metadata.has("requestUUID") ? metadata.get("requestUUID").asText() : UUIDs.timeBased().toString());
        builder.setExpirationTime(metadata.has("expirationTime") ? metadata.get("expirationTime").asLong() : System.currentTimeMillis() + 60000);
        builder.setOneway(metadata.has("oneway") ? metadata.get("oneway").asBoolean() : true);
        if (metadata.has("originServiceId")) {
            builder.setOriginServiceId(metadata.get("originServiceId").asText());
        }
        return builder.build();
    }

}
