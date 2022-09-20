use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized, not owner")]
    UnauthorizedOwner {},

    #[error("Custom Error val: {val:?}")]
    CustomError { val: String },
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
    #[error("Approval from owner is required")]
    ApproveRequired(),

    #[error("Tollgate is not expired yet")]
    TollgateNotExpired(),

    #[error("No reward to be claimed")]
    NoReward(),

    #[error("Funds is not passed")]
    NoFundsPass(),

    #[error("Invalid claim period")]
    InvalidClaimPeriod(),
}
