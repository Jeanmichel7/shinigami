use crate::errors::Error;

// sigOpsDelta is both the starting budget for sig ops for tapscript
// verification, as well as the decrease in the total budget when we encounter
// a signature.
const SIGOPSDELTA: usize = 50;
// blankCodeSepValue is the value of the code separator position in the
// tapscript sighash when no code separator was found in the script.
const BLANKCODESEPVALUE: usize = 0;

// taprootExecutionCtx houses the special context-specific information we need
// to validate a taproot script spend. This includes the annex, the running sig
// op count tally, and other relevant information.
#[derive(Default, Drop)]
pub struct TaprootExecutionCtx {
    annex: ByteArray,
    codeSepPos: usize,
    tapLeafHash: ByteArray,
    sigOpsBudget: usize,
    pub mustSucceed: bool
}

#[generate_trait()]
pub impl TaprootExecutionCtxImpl of TaprootExecutionCtxTrait {
    // tallysigOp attempts to decrease the current sig ops budget by sigOpsDelta.
    // An error is returned if after subtracting the delta, the budget is below
    // zero.
    fn tallysig_op(ref self: TaprootExecutionCtx) -> Result<(), felt252> {
        self.sigOpsBudget -= SIGOPSDELTA;
        if self.sigOpsBudget < 0 {
            return Result::Err(Error::TAPROOT_MAX_SIGOPS);
        }
        Result::Ok(())
    }
}

// newTaprootExecutionCtx returns a fresh instance of the taproot execution
// context.
fn newTaprootExecutionCtx(inputWitnessSize: u32) -> TaprootExecutionCtx {
    TaprootExecutionCtx {
        codeSepPos: BLANKCODESEPVALUE,
        sigOpsBudget: SIGOPSDELTA + inputWitnessSize,
        ..Default::default()
    }
}
// pub impl TaprootContextDefault of Default<TaprootExecutionCtx> {
//     fn default() -> TaprootExecutionCtx {
//         TaprootExecutionCtx {
//             annex: Default::default(),
//             codeSepPos: Default::default(),
//             tapLeafHash: Default::default(),
//             sigOpsBudget: Default::default(),
//             mustSucceed: Default::default(),
//         }
//     }
// }


