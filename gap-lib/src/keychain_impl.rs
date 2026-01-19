//! Low-level keychain implementation with access group support
//!
//! This module provides direct access to macOS Keychain APIs with support for
//! access groups, which allows keychain items to survive binary re-signing.

use crate::Result;
use core_foundation::base::{CFGetTypeID, TCFType, ToVoid};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFRelease, CFTypeRef};
use core_foundation_sys::data::CFDataRef;
use core_foundation_sys::base::OSStatus;
use security_framework_sys::base::{errSecItemNotFound, errSecSuccess};
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrAccessGroup, kSecAttrService, kSecClass, kSecClassGenericPassword,
    kSecReturnData, kSecValueData, kSecUseDataProtectionKeychain,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};

/// Convert OSStatus to Result
fn cvt(status: OSStatus) -> Result<()> {
    if status == errSecSuccess {
        Ok(())
    } else {
        Err(crate::GapError::storage(format!(
            "Keychain operation failed with status: {}",
            status
        )))
    }
}

/// Set a generic password with optional access group and Data Protection Keychain
pub fn set_generic_password_with_access_group(
    service: &str,
    account: &str,
    password: &[u8],
    access_group: Option<&str>,
    use_data_protection: bool,
) -> Result<()> {
    // Delete existing entry first
    let _ = delete_generic_password_with_access_group(service, account, access_group, use_data_protection);

    // Build add dictionary
    let mut dict = CFMutableDictionary::from_CFType_pairs(&[]);

    let class_key = unsafe { CFString::wrap_under_get_rule(kSecClass) };
    let class_value = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };
    dict.add(&class_key.to_void(), &class_value.to_void());

    let service_key = unsafe { CFString::wrap_under_get_rule(kSecAttrService) };
    dict.add(&service_key.to_void(), &CFString::from(service).to_void());

    let account_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };
    dict.add(&account_key.to_void(), &CFString::from(account).to_void());

    if let Some(group) = access_group {
        let group_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessGroup) };
        dict.add(&group_key.to_void(), &CFString::from(group).to_void());
    }

    let data_key = unsafe { CFString::wrap_under_get_rule(kSecValueData) };
    let data = CFData::from_buffer(password);
    dict.add(&data_key.to_void(), &data.to_void());

    // Use Data Protection Keychain for entitlement-based access (macOS 10.15+)
    // This eliminates password prompts by using entitlements instead of ACLs
    if use_data_protection {
        let dpk_key = unsafe { CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain) };
        dict.add(&dpk_key.to_void(), &CFBoolean::from(true).to_void());
    }

    let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
    cvt(status)
}

/// Get a generic password with optional access group and Data Protection Keychain
pub fn get_generic_password_with_access_group(
    service: &str,
    account: &str,
    access_group: Option<&str>,
    use_data_protection: bool,
) -> Result<Option<Vec<u8>>> {
    // Build query dictionary
    let mut dict = CFMutableDictionary::from_CFType_pairs(&[]);

    let class_key = unsafe { CFString::wrap_under_get_rule(kSecClass) };
    let class_value = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };
    dict.add(&class_key.to_void(), &class_value.to_void());

    let service_key = unsafe { CFString::wrap_under_get_rule(kSecAttrService) };
    dict.add(&service_key.to_void(), &CFString::from(service).to_void());

    let account_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };
    dict.add(&account_key.to_void(), &CFString::from(account).to_void());

    if let Some(group) = access_group {
        let group_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessGroup) };
        dict.add(&group_key.to_void(), &CFString::from(group).to_void());
    }

    let return_data_key = unsafe { CFString::wrap_under_get_rule(kSecReturnData) };
    dict.add(
        &return_data_key.to_void(),
        &CFBoolean::from(true).to_void(),
    );

    // Use Data Protection Keychain for entitlement-based access (macOS 10.15+)
    // This eliminates password prompts by using entitlements instead of ACLs
    if use_data_protection {
        let dpk_key = unsafe { CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain) };
        dict.add(&dpk_key.to_void(), &CFBoolean::from(true).to_void());
    }

    let mut ret: CFTypeRef = std::ptr::null_mut();
    let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut ret) };

    if status == errSecItemNotFound {
        return Ok(None);
    }

    cvt(status)?;

    if !ret.is_null() {
        let type_id = unsafe { CFGetTypeID(ret) };
        if type_id == CFData::type_id() {
            let data = unsafe { CFData::wrap_under_create_rule(ret as CFDataRef) };
            let vec = data.bytes().to_vec();
            Ok(Some(vec))
        } else {
            unsafe { CFRelease(ret) };
            Err(crate::GapError::storage(
                "Unexpected data type from keychain",
            ))
        }
    } else {
        Ok(None)
    }
}

/// Delete a generic password with optional access group and Data Protection Keychain
pub fn delete_generic_password_with_access_group(
    service: &str,
    account: &str,
    access_group: Option<&str>,
    use_data_protection: bool,
) -> Result<()> {
    // Build query dictionary
    let mut dict = CFMutableDictionary::from_CFType_pairs(&[]);

    let class_key = unsafe { CFString::wrap_under_get_rule(kSecClass) };
    let class_value = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };
    dict.add(&class_key.to_void(), &class_value.to_void());

    let service_key = unsafe { CFString::wrap_under_get_rule(kSecAttrService) };
    dict.add(&service_key.to_void(), &CFString::from(service).to_void());

    let account_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };
    dict.add(&account_key.to_void(), &CFString::from(account).to_void());

    if let Some(group) = access_group {
        let group_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccessGroup) };
        dict.add(&group_key.to_void(), &CFString::from(group).to_void());
    }

    // Use Data Protection Keychain for entitlement-based access (macOS 10.15+)
    // This eliminates password prompts by using entitlements instead of ACLs
    if use_data_protection {
        let dpk_key = unsafe { CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain) };
        dict.add(&dpk_key.to_void(), &CFBoolean::from(true).to_void());
    }

    let status = unsafe { SecItemDelete(dict.as_concrete_TypeRef()) };

    // Idempotent - OK if item not found
    if status == errSecItemNotFound {
        Ok(())
    } else {
        cvt(status)
    }
}
