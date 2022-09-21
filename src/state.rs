use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Timestamp};
use cw_storage_plus::{Item, Map};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub owner: Addr,
    pub starting_time: Timestamp,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct VestingInfo {
    pub reward: u128,
    pub counter: u8,
    pub approve_tollgate_time: Timestamp,
    pub remaining_reward: u128,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const VESTING_INFO: Map<Addr, VestingInfo> = Map::new("vesting_info");
