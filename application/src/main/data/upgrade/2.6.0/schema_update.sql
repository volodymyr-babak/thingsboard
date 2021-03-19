--
-- Copyright © 2016-2020 The Thingsboard Authors
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

CREATE TABLE IF NOT EXISTS edge (
    id varchar(31) NOT NULL CONSTRAINT edge_pkey PRIMARY KEY,
    additional_info varchar,
    customer_id varchar(31),
    root_rule_chain_id varchar(31),
    type varchar(255),
    name varchar(255),
    label varchar(255),
    routing_key varchar(255),
    secret varchar(255),
    edge_license_key varchar(30),
    cloud_endpoint varchar(255),
    search_text varchar(255),
    tenant_id varchar(31),
    CONSTRAINT edge_name_unq_key UNIQUE (tenant_id, name),
    CONSTRAINT edge_routing_key_unq_key UNIQUE (routing_key)
);

CREATE TABLE IF NOT EXISTS edge_event (
    id varchar(31) NOT NULL CONSTRAINT edge_event_pkey PRIMARY KEY,
    edge_id varchar(31),
    edge_event_type varchar(255),
    edge_event_uid varchar(255),
    entity_id varchar(31),
    edge_event_action varchar(255),
    body varchar(10000000),
    tenant_id varchar(31),
    ts bigint NOT NULL
);