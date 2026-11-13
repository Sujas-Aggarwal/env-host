//go:build darwin && cgo

package auth

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework LocalAuthentication -framework Foundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>
int envh_local_auth_can_evaluate(void);
int envh_local_auth_evaluate(void);

static CFStringRef envh_string(const char *s) {
    return CFStringCreateWithCString(kCFAllocatorDefault, s, kCFStringEncodingUTF8);
}
static CFMutableDictionaryRef envh_query(const char *account) {
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFStringRef service = envh_string("env-host.project-key.v1");
    CFStringRef name = envh_string(account);
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(q, kSecAttrService, service);
    CFDictionarySetValue(q, kSecAttrAccount, name);
    CFRelease(service); CFRelease(name);
    return q;
}
static OSStatus envh_add(const char *account, const unsigned char *key, int length) {
    CFMutableDictionaryRef q = envh_query(account);
    CFDataRef value = CFDataCreate(kCFAllocatorDefault, key, length);
    CFDictionarySetValue(q, kSecValueData, value);
    CFDictionarySetValue(q, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
    OSStatus status = SecItemAdd(q, NULL);
    CFRelease(value); CFRelease(q);
    return status;
}
static OSStatus envh_read(const char *account, unsigned char *output, int capacity, int *length) {
    CFMutableDictionaryRef q = envh_query(account);
    CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(q, &result);
    if (status == errSecSuccess) {
        if (!result || CFGetTypeID(result) != CFDataGetTypeID() || CFDataGetLength((CFDataRef)result) > capacity) status = errSecDecode;
        else { *length = (int)CFDataGetLength((CFDataRef)result); memcpy(output, CFDataGetBytePtr((CFDataRef)result), *length); }
    }
    if(result) CFRelease(result);
    CFRelease(q);
    return status;
}
static OSStatus envh_delete(const char *account) {
    CFMutableDictionaryRef q = envh_query(account);
    OSStatus status = SecItemDelete(q); CFRelease(q); return status;
}
*/
import "C"

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"unsafe"
)

const Available = true
const Method = "keychain"

// Ready checks that macOS can offer user authentication without prompting.
func Ready() error {
	if code := int(C.envh_local_auth_can_evaluate()); code != 0 {
		return fmt.Errorf("macOS Touch ID or login-password authentication is unavailable (LocalAuthentication error %d)", code)
	}
	return nil
}

// Authenticate asks macOS to verify the user with Touch ID or the login password.
func Authenticate() error {
	if code := int(C.envh_local_auth_evaluate()); code != 0 {
		return fmt.Errorf("macOS authentication failed or was canceled (LocalAuthentication error %d)", code)
	}
	return nil
}

// Probe creates a disposable Keychain item, verifies the user, reads it, and deletes it.
func Probe() error {
	if err := Ready(); err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	locator := "envh-probe-" + hex.EncodeToString(nonce)
	key, err := Create(locator)
	if err != nil {
		return err
	}
	read, readErr := Read(locator)
	deleteErr := Delete(locator)
	if readErr != nil {
		return readErr
	}
	if deleteErr != nil {
		return deleteErr
	}
	if subtle.ConstantTimeCompare([]byte(key), []byte(read)) != 1 {
		return fmt.Errorf("Keychain returned a different project key")
	}
	return nil
}

// Create stores a fresh random project key in the user's login Keychain.
func Create(locator string) (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	defer clear(key)
	account := C.CString(locator)
	defer C.free(unsafe.Pointer(account))
	status := C.envh_add(account, (*C.uchar)(unsafe.Pointer(&key[0])), C.int(len(key)))
	if status != C.errSecSuccess {
		return "", fmt.Errorf("cannot create project key in macOS Keychain (OSStatus %d)", int(status))
	}
	return hex.EncodeToString(key), nil
}

func Read(locator string) (string, error) {
	if err := Authenticate(); err != nil {
		return "", err
	}
	account := C.CString(locator)
	defer C.free(unsafe.Pointer(account))
	key := make([]byte, 32)
	defer clear(key)
	var n C.int
	status := C.envh_read(account, (*C.uchar)(unsafe.Pointer(&key[0])), C.int(len(key)), &n)
	if status != C.errSecSuccess || n != 32 {
		return "", fmt.Errorf("cannot read project key from macOS Keychain (OSStatus %d)", int(status))
	}
	return hex.EncodeToString(key), nil
}

func Delete(locator string) error {
	account := C.CString(locator)
	defer C.free(unsafe.Pointer(account))
	status := C.envh_delete(account)
	if status != C.errSecSuccess && status != C.errSecItemNotFound {
		return fmt.Errorf("cannot remove project key from macOS Keychain (OSStatus %d)", int(status))
	}
	return nil
}
