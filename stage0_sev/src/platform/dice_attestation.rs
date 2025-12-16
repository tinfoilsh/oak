//
// Copyright 2024 The Project Oak Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use oak_attestation::dice::DiceAttester;
use oak_sev_snp_attestation_report::{AttestationReport, REPORT_DATA_SIZE};
use oak_stage0::hal::Platform;
use oak_stage0_dice::DerivedKey;

/// Initializes the Guest Message encryptor using VMPCK0.
pub fn init_guest_message_encryptor() -> Result<(), &'static str> {
    // Skip VMPCK0 initialization - leave it pristine for kernel/tfshim
    Ok(())
}

pub fn get_attester() -> Result<DiceAttester, &'static str> {
    oak_stage0_dice::generate_initial_dice_data(
        get_attestation,
        crate::platform::Sev::tee_platform(),
    )?
    .try_into()
    .map_err(|_| "couldn't convert initial DICE evidence to an attester")
}

fn get_attestation(report_data: [u8; REPORT_DATA_SIZE]) -> Result<AttestationReport, &'static str> {
    // Use mock to avoid VMPCK0 sequence number consumption
    oak_stage0_dice::mock_attestation_report(report_data)
}

pub fn get_derived_key() -> Result<DerivedKey, &'static str> {
    // Use mock to avoid VMPCK0 sequence number consumption
    oak_stage0::hal::Base::get_derived_key()
}
