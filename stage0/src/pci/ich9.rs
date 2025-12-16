//
// Copyright 2025 The Project Oak Authors
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

//! ICH9 (I/O Controller Hub 9) initialization for Q35 chipset.
//!
//! This module initializes the ICH9 LPC bridge's ACPI power management registers.
//! Without this initialization, QEMU generates ACPI FADT tables with zero PM1aEventBlock
//! address, causing Linux to fail ACPI initialization.
//!
//! The ICH9 LPC bridge is at PCI address 00:1F.0

use crate::pci::{config_access::ConfigAccess, device::Bdf};

/// ICH9 LPC Bridge PCI address: Bus 0, Device 0x1F, Function 0
const ICH9_LPC_BUS: u8 = 0;
const ICH9_LPC_DEV: u8 = 0x1F;
const ICH9_LPC_FN: u8 = 0;

/// PCI Configuration Space register offsets (in DWORDs, as ConfigAccess uses DWORD addressing)
/// ICH9_LPC_PMBASE is at byte offset 0x40, so DWORD offset is 0x10
const ICH9_LPC_PMBASE_DWORD: u8 = 0x10;
/// ICH9_LPC_ACPI_CTRL is at byte offset 0x44, so DWORD offset is 0x11
const ICH9_LPC_ACPI_CTRL_DWORD: u8 = 0x11;

/// PM Base I/O address. Standard value used by OVMF and SeaBIOS.
const ICH9_PMBASE_VALUE: u32 = 0x0600;
/// Mask for PM Base address bits (bits 15:7)
const ICH9_PMBASE_MASK: u32 = 0x0000_FF80;

/// ACPI Enable bit in ACPI_CTRL register (bit 7 of byte at offset 0x44)
/// Since we read the DWORD at 0x44, bit 7 is in the low byte.
const ICH9_ACPI_CTRL_ACPI_EN: u32 = 0x80;

/// Initialize ICH9 LPC bridge ACPI Power Management registers.
///
/// This must be called before accessing ACPI tables via fw_cfg, as QEMU
/// regenerates ACPI tables on first fw_cfg access using the current PM base value.
///
/// # What this does
///
/// 1. Sets PM Base Address register to 0x600 (standard PM I/O port base)
/// 2. Enables ACPI by setting the ACPI_EN bit
///
/// After this, QEMU will generate FADT with correct PM1aEventBlock = 0x600.
pub fn init_ich9_pm(config_access: &mut dyn ConfigAccess) -> Result<(), &'static str> {
    let lpc_bdf = Bdf::new(ICH9_LPC_BUS, ICH9_LPC_DEV, ICH9_LPC_FN)?;

    // Verify the LPC bridge exists
    let vendor_device = config_access.read(lpc_bdf, 0x00)?;
    let vendor_id = (vendor_device & 0xFFFF) as u16;
    if vendor_id == 0xFFFF || vendor_id == 0x0000 {
        return Err("ICH9 LPC bridge not found");
    }

    // Read current PMBASE value
    let pmbase = config_access.read(lpc_bdf, ICH9_LPC_PMBASE_DWORD)?;

    // Set PM Base Address to 0x600
    // Clear the address bits and set our value
    let new_pmbase = (pmbase & !ICH9_PMBASE_MASK) | ICH9_PMBASE_VALUE;
    config_access.write(lpc_bdf, ICH9_LPC_PMBASE_DWORD, new_pmbase)?;

    // Read ACPI control register and enable ACPI
    let acpi_ctrl = config_access.read(lpc_bdf, ICH9_LPC_ACPI_CTRL_DWORD)?;
    config_access.write(lpc_bdf, ICH9_LPC_ACPI_CTRL_DWORD, acpi_ctrl | ICH9_ACPI_CTRL_ACPI_EN)?;

    log::info!(
        "ICH9: PM Base set to 0x{:04X}, ACPI enabled",
        ICH9_PMBASE_VALUE
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::config_access::MockConfigAccess;
    use googletest::prelude::*;

    #[gtest]
    fn test_init_ich9_pm_success() {
        let mut mock = MockConfigAccess::new();

        // Expect read of vendor/device ID
        mock.expect_read()
            .withf(|bdf, offset| {
                *bdf == Bdf::new(0, 0x1F, 0).unwrap() && *offset == 0x00
            })
            .returning(|_, _| Ok(0x3A18_8086)); // Intel ICH9 LPC

        // Expect read of PMBASE
        mock.expect_read()
            .withf(|bdf, offset| {
                *bdf == Bdf::new(0, 0x1F, 0).unwrap() && *offset == ICH9_LPC_PMBASE_DWORD
            })
            .returning(|_, _| Ok(0x0000_0001)); // Some initial value

        // Expect write of PMBASE with 0x600
        mock.expect_write()
            .withf(|bdf, offset, value| {
                *bdf == Bdf::new(0, 0x1F, 0).unwrap()
                    && *offset == ICH9_LPC_PMBASE_DWORD
                    && (*value & ICH9_PMBASE_MASK) == ICH9_PMBASE_VALUE
            })
            .returning(|_, _, _| Ok(()));

        // Expect read of ACPI_CTRL
        mock.expect_read()
            .withf(|bdf, offset| {
                *bdf == Bdf::new(0, 0x1F, 0).unwrap() && *offset == ICH9_LPC_ACPI_CTRL_DWORD
            })
            .returning(|_, _| Ok(0x0000_0000));

        // Expect write of ACPI_CTRL with ACPI_EN set
        mock.expect_write()
            .withf(|bdf, offset, value| {
                *bdf == Bdf::new(0, 0x1F, 0).unwrap()
                    && *offset == ICH9_LPC_ACPI_CTRL_DWORD
                    && (*value & ICH9_ACPI_CTRL_ACPI_EN) != 0
            })
            .returning(|_, _, _| Ok(()));

        let result = init_ich9_pm(&mut mock);
        assert_that!(result, ok(eq(())));
    }

    #[gtest]
    fn test_init_ich9_pm_no_device() {
        let mut mock = MockConfigAccess::new();

        // Return 0xFFFF for vendor ID (no device)
        mock.expect_read()
            .withf(|bdf, offset| {
                *bdf == Bdf::new(0, 0x1F, 0).unwrap() && *offset == 0x00
            })
            .returning(|_, _| Ok(0xFFFF_FFFF));

        let result = init_ich9_pm(&mut mock);
        assert_that!(result, err(anything()));
    }
}

