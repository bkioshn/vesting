#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Timestamp,
};
use cw2::set_contract_version;
use cw_asset::Asset;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, VestingInfo, CONFIG, VESTING_INFO};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:vesting";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
const MONTH: u64 = 60 * 60 * 24 * 30;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    // Check whether funds is passed
    if info.funds.is_empty() {
        return Err(ContractError::NoFundsPass());
    }

    CONFIG.save(
        deps.storage,
        &Config {
            owner: msg.owner.clone(),
            starting_time: env.block.time,
        },
    )?;

    for (i, _) in msg.users.iter().enumerate() {
        // Validate address
        deps.api.addr_validate(&msg.users[i].to_string())?;
        VESTING_INFO.save(
            deps.storage,
            msg.users[i].clone(),
            &VestingInfo {
                reward: msg.rewards[i],
                counter: 0u8,
                approve_tollgate_time: env.block.time,
                remaining_reward: msg.rewards[i],
            },
        )?;
    }

    // Change later
    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender.clone()))
}

// Check whether user vestingInfo amount fall into which case
// 0 - 75 3 months
// 75 - 150 6 months
// 150 - 300 9 months
// > 300 12 months
fn cal_reward_month(amount: u128) -> u8 {
    match amount {
        0..=75 => 3,
        76..=150 => 6,
        151..=300 => 9,
        301.. => 12,
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Claim {} => claim_reward(deps, info, env),
        ExecuteMsg::Approve { user } => approve(deps, info, env, user),
    }
}

pub fn claim_reward(deps: DepsMut, info: MessageInfo, env: Env) -> Result<Response, ContractError> {
    let vesting_info = VESTING_INFO.load(deps.storage, info.sender.clone())?;

    // Determine how many month should this reward be distributed
    let month_reward = cal_reward_month(vesting_info.reward);

    // Check whether user has reward to claim or not
    if vesting_info.remaining_reward == 0 {
        return Err(ContractError::RewardHasBeenClaimed());
    }

    // Check if Tollgate is approved from owner less than 3 months
    if vesting_info.approve_tollgate_time.seconds() + MONTH * 3 < env.block.time.seconds() {
        return Err(ContractError::ApproveRequired());
    }

    // Check whether associated user has reward to claim or not
    if vesting_info.reward == 0 {
        return Err(ContractError::NoReward());
    }

    let starting_time = CONFIG.load(deps.storage)?.starting_time.seconds();

    // Amount factor that user can claim
    // eg. 0 = user can claim 0, 1 = user can claim 1 time
    let amount_factor =
        (env.block.time.seconds() - starting_time) / MONTH - (vesting_info.counter as u64);
    if amount_factor == 0 {
        return Err(ContractError::InvalidClaimPeriod());
    }

    let mut amount = vesting_info.reward / (month_reward as u128) * (amount_factor as u128);
    if amount_factor + vesting_info.counter as u64 >= month_reward as u64 {
        amount = vesting_info.remaining_reward;
    }

    let asset = Asset::native("uluna", amount);

    VESTING_INFO.update(
        deps.storage,
        info.sender.clone(),
        |state| -> Result<_, ContractError> {
            match state {
                Some(o) => Ok(VestingInfo {
                    reward: o.reward,
                    counter: o.counter + amount_factor as u8,
                    approve_tollgate_time: o.approve_tollgate_time,
                    remaining_reward: o.remaining_reward - amount,
                }),
                None => Ok(VestingInfo {
                    reward: 0,
                    counter: 0,
                    approve_tollgate_time: Timestamp::from_seconds(0),
                    remaining_reward: 0,
                }),
            }
        },
    )?;
    Ok(Response::new()
        .add_attribute("method", "claim")
        .add_attribute("amount", amount.to_string())
        .add_attribute("user_reward_amount", vesting_info.reward.to_string())
        .add_attribute("month_reward", month_reward.to_string())
        .add_attribute("amount_factor", amount_factor.to_string())
        .add_attribute("starting_time", starting_time.to_string())
        .add_attribute("MONTH", MONTH.to_string())
        .add_attribute("counter", vesting_info.counter.to_string())
        .add_message(asset.transfer_msg(info.sender)?))
}

pub fn approve(
    deps: DepsMut,
    info: MessageInfo,
    env: Env,
    user: String,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    if config.owner != info.sender {
        return Err(ContractError::UnauthorizedOwner {});
    }
    let vesting_info = VESTING_INFO.load(deps.storage, Addr::unchecked(&user))?;

    let prev_3_month_from_today = env.block.time.seconds() - MONTH * 3;
    if prev_3_month_from_today < vesting_info.approve_tollgate_time.seconds() {
        return Err(ContractError::TollgateNotExpired());
    }
    VESTING_INFO.save(
        deps.storage,
        Addr::unchecked(&user),
        &VestingInfo {
            reward: vesting_info.reward,
            counter: vesting_info.counter,
            approve_tollgate_time: env.block.time,
            remaining_reward: vesting_info.remaining_reward,
        },
    )?;
    Ok(Response::new()
        .add_attribute("method", "approve")
        .add_attribute("approve_tollgate_time", env.block.time.to_string()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetVestingConfig {} => to_binary(&query_vesting_config(deps)?),
        QueryMsg::GetUsersVestingInfo { user } => to_binary(&query_users_vesting_info(deps, user)?),
    }
}

fn query_vesting_config(deps: Deps) -> StdResult<Config> {
    let config = CONFIG.load(deps.storage)?;
    Ok(Config {
        owner: config.owner,
        starting_time: config.starting_time,
    })
}

fn query_users_vesting_info(deps: Deps, user: Addr) -> StdResult<VestingInfo> {
    let vesting_info = VESTING_INFO.load(deps.storage, user)?;
    Ok(VestingInfo {
        reward: vesting_info.reward,
        counter: vesting_info.counter,
        approve_tollgate_time: vesting_info.approve_tollgate_time,
        remaining_reward: vesting_info.remaining_reward,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies_with_balance, mock_env, mock_info};
    use cosmwasm_std::{coins, from_binary, Addr, BankMsg, CosmosMsg, Storage};

    const DAY: u64 = 60 * 60 * 24;

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies_with_balance(&coins(200000000, "uluna"));
        let info = mock_info("owner", &coins(10000000, "uluna"));
        let msg = InstantiateMsg {
            owner: Addr::unchecked("owner"),
            users: vec![Addr::unchecked("alice"), Addr::unchecked("bob")],
            rewards: vec![10u128, 200u128],
        };

        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Check config state
        let config_res = query(deps.as_ref(), mock_env(), QueryMsg::GetVestingConfig {}).unwrap();
        let config: Config = from_binary(&config_res).unwrap();
        assert_eq!(
            Config {
                owner: Addr::unchecked("owner"),
                starting_time: mock_env().block.time,
            },
            config
        );

        // Check vesting_info state
        let alice_vesting_info_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetUsersVestingInfo {
                user: Addr::unchecked("alice"),
            },
        )
        .unwrap();
        let alice_vesting_info: VestingInfo = from_binary(&alice_vesting_info_res).unwrap();
        assert_eq!(
            VestingInfo {
                reward: 10u128,
                counter: 0u8,
                approve_tollgate_time: mock_env().block.time,
                remaining_reward: 10u128
            },
            alice_vesting_info
        );
    }

    #[test]
    fn approve() {
        let mut deps = mock_dependencies_with_balance(&coins(0, "uluna"));
        let mut info = mock_info("owner", &coins(10000000, "uluna"));
        let mut env = mock_env();
        let msg = InstantiateMsg {
            owner: Addr::unchecked("owner"),
            users: vec![Addr::unchecked("alice"), Addr::unchecked("bob")],
            rewards: vec![20u128, 200u128],
        };
        let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        info.sender = Addr::unchecked("owner");

        // Approve when tollgate hasn't expired
        env.block.time = Timestamp::from_seconds(env.block.time.seconds() + MONTH);
        let msg = ExecuteMsg::Approve {
            user: "alice".to_string(),
        };
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
        match res {
            Err(ContractError::TollgateNotExpired {}) => {}
            _ => panic!("Must return tollgate not expired error"),
        }

        // Approve when tollgate already expired
        env.block.time = Timestamp::from_seconds(env.block.time.seconds() + MONTH * 3);
        let msg = ExecuteMsg::Approve {
            user: "alice".to_string(),
        };
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        let alice_vesting_info_res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::GetUsersVestingInfo {
                user: Addr::unchecked("alice"),
            },
        )
        .unwrap();
        let alice_vesting_info: VestingInfo = from_binary(&alice_vesting_info_res).unwrap();
        assert_eq!(
            VestingInfo {
                reward: 20u128,
                counter: 0u8,
                approve_tollgate_time: env.block.time,
                remaining_reward: 20u128,
            },
            alice_vesting_info
        );
    }

    #[test]
    fn claim() {
        let mut deps = mock_dependencies_with_balance(&coins(0, "uluna"));
        let mut info = mock_info("owner", &coins(10000000, "uluna"));
        let mut env = mock_env();
        let msg = InstantiateMsg {
            owner: Addr::unchecked("owner"),
            users: vec![Addr::unchecked("alice"), Addr::unchecked("bob")],
            rewards: vec![20u128, 200u128],
        };
        let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // 1 month pass -> able to claim
        // Alice reward is 20, so need to be distributed in 3 month
        // reward per month 20 / 3 ~= 6
        env.block.time = Timestamp::from_seconds(env.block.time.seconds() + MONTH);
        info.sender = Addr::unchecked("alice");
        let msg = ExecuteMsg::Claim {};
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        assert_eq!(
            res.messages[0].msg,
            CosmosMsg::Bank(BankMsg::Send {
                to_address: "alice".to_string(),
                amount: coins(6, "uluna"),
            })
        );

        // Alice claim again
        env.block.time = Timestamp::from_seconds(env.block.time.seconds() + DAY);
        let msg = ExecuteMsg::Claim {};
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
        match res {
            Err(ContractError::InvalidClaimPeriod {}) => {}
            _ => panic!("Must return invalid claim period error"),
        }

        // Approve
        // ! Fix: shouldn't call this function? directly change state
        env.block.time = Timestamp::from_seconds(env.block.time.seconds() + MONTH * 2 + DAY * 10);
        info.sender = Addr::unchecked("owner");
        let msg = ExecuteMsg::Approve {
            user: "alice".to_string(),
        };
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // let vesting_info = VESTING_INFO.load(&mut deps.storage, Addr::unchecked("alice")).unwrap();
        // VESTING_INFO.save(
        //     &mut deps.storage,
        //     Addr::unchecked("owner"),
        //     &VestingInfo {
        //         reward: vesting_info.reward,
        //         counter: vesting_info.counter,
        //         approve_tollgate_time: env.block.time,
        //     },
        // ).unwrap();

        // Exacly 3 month pass -> Alice hasn't claim her 2nd month
        // Alice should recieve reward for her 2 month and the rest
        info.sender = Addr::unchecked("alice");
        let msg = ExecuteMsg::Claim {};
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        assert_eq!(
            res.messages[0].msg,
            CosmosMsg::Bank(BankMsg::Send {
                to_address: "alice".to_string(),
                amount: coins(14, "uluna"),
            })
        );

        // Alice already claims all her reward
        env.block.time = Timestamp::from_seconds(env.block.time.seconds() + MONTH);
        let msg = ExecuteMsg::Claim {};
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
        match res {
            Err(ContractError::NoReward {}) => {}
            _ => panic!("Must return no reward error"),
        }
    }

    #[test]
    fn claim_all_at_once() {
        let mut deps = mock_dependencies_with_balance(&coins(0, "uluna"));
        let mut info = mock_info("owner", &coins(10000000, "uluna"));
        let mut env = mock_env();
        let msg = InstantiateMsg {
            owner: Addr::unchecked("owner"),
            users: vec![Addr::unchecked("alice"), Addr::unchecked("bob")],
            rewards: vec![20u128, 200u128],
        };
        let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        env.block.time = Timestamp::from_seconds(env.block.time.seconds() + MONTH * 3 + DAY);
        info.sender = Addr::unchecked("owner");
        let msg = ExecuteMsg::Approve {
            user: "alice".to_string(),
        };
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        env.block.time = Timestamp::from_seconds(env.block.time.seconds() + MONTH * 2);
        info.sender = Addr::unchecked("alice");
        let msg = ExecuteMsg::Claim {};
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        assert_eq!(
            res.messages[0].msg,
            CosmosMsg::Bank(BankMsg::Send {
                to_address: "alice".to_string(),
                amount: coins(20, "uluna"),
            })
        );
    }

    #[test]
    fn claim_patial_then_all() {
        let mut deps = mock_dependencies_with_balance(&coins(0, "uluna"));
        let mut info = mock_info("owner", &coins(10000000, "uluna"));
        let mut env = mock_env();
        let msg = InstantiateMsg {
            owner: Addr::unchecked("owner"),
            users: vec![Addr::unchecked("alice"), Addr::unchecked("bob")],
            rewards: vec![20u128, 200u128],
        };
        let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        env.block.time = Timestamp::from_seconds(env.block.time.seconds() + MONTH);
        info.sender = Addr::unchecked("alice");
        let msg = ExecuteMsg::Claim {};
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        assert_eq!(
            res.messages[0].msg,
            CosmosMsg::Bank(BankMsg::Send {
                to_address: "alice".to_string(),
                amount: coins(6, "uluna"),
            })
        );

        env.block.time = Timestamp::from_seconds(env.block.time.seconds() + MONTH * 3);
        info.sender = Addr::unchecked("owner");
        let msg = ExecuteMsg::Approve {
            user: "alice".to_string(),
        };
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        env.block.time = Timestamp::from_seconds(env.block.time.seconds() + MONTH * 2);
        info.sender = Addr::unchecked("alice");
        let msg = ExecuteMsg::Claim {};
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        assert_eq!(
            res.messages[0].msg,
            CosmosMsg::Bank(BankMsg::Send {
                to_address: "alice".to_string(),
                amount: coins(14, "uluna"),
            })
        );

        env.block.time = Timestamp::from_seconds(env.block.time.seconds() + MONTH);
        let msg = ExecuteMsg::Claim {};
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg);
        match res {
            Err(ContractError::NoReward {}) => {}
            _ => panic!("Must return no reward error"),
        }
    }
}
