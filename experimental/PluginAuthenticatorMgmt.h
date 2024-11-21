// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef __PLUGIN_AUTHENTICATOR_MGMT_H_
#define __PLUGIN_AUTHENTICATOR_MGMT_H_

#pragma once

#include <winapifamily.h>

#pragma region Desktop Family or OneCore Family
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_APP | WINAPI_PARTITION_SYSTEM)

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WINAPI
#define WINAPI __stdcall
#endif

#ifndef __midl

typedef enum _EXPERIMENTAL_PLUGIN_AUTHENTICATOR_STATE
{
    PluginAuthenticatorState_Unknown = 0,
    PluginAuthenticatorState_Disabled,
    PluginAuthenticatorState_Enabled
} EXPERIMENTAL_PLUGIN_AUTHENTICATOR_STATE;

//
// Plugin Authenticator API: WebAuthNPluginGetAuthenticatorState: Get Plugin Authenticator State
//
HRESULT
WINAPI
EXPERIMENTAL_WebAuthNPluginGetAuthenticatorState(
    _In_ LPCWSTR pwszPluginClsId,
    _Out_ EXPERIMENTAL_PLUGIN_AUTHENTICATOR_STATE* pluginAuthenticatorState 
);

//
// Plugin Authenticator API: WebAuthNAddPluginAuthenticator: Add Plugin Authenticator
//

typedef struct _EXPERIMENTAL_WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS {
    // Authenticator Name
    LPCWSTR pwszAuthenticatorName;

    // Plugin COM ClsId
    LPCWSTR pwszPluginClsId;

    // Plugin RPID (Optional. Required for a nested WebAuthN call originating from a plugin)
    LPCWSTR pwszPluginRpId;

    // Plugin Authenticator Logo for the Light themes. base64 svg (Optional)
    LPCWSTR pwszLightThemeLogo;

    // Plugin Authenticator Logo for the Dark themes. base64 svg (Optional)
    LPCWSTR pwszDarkThemeLogo;

    // CTAP CBOR encoded authenticatorGetInfo
    DWORD cbAuthenticatorInfo;
    _Field_size_bytes_(cbAuthenticatorInfo)
    PBYTE pbAuthenticatorInfo;

} EXPERIMENTAL_WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS, *EXPERIMENTAL_PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS;
typedef const EXPERIMENTAL_WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS *EXPERIMENTAL_PCWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS;

typedef struct _EXPERIMENTAL_WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE {
    // Plugin operation signing Public Key - Used to sign the request in the EXPERIMENTAL_PluginPerformOperation. Refer pluginauthenticator.h.
    DWORD cbOpSignPubKey;
    _Field_size_bytes_(cbOpSignPubKey)
    PBYTE pbOpSignPubKey;

} EXPERIMENTAL_WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE, *EXPERIMENTAL_PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE;
typedef const EXPERIMENTAL_WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE *EXPERIMENTAL_PCWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE;

HRESULT
WINAPI
EXPERIMENTAL_WebAuthNPluginAddAuthenticator(
    _In_ EXPERIMENTAL_PCWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS pPluginAddAuthenticatorOptions,
    _Outptr_result_maybenull_ EXPERIMENTAL_PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE *ppPluginAddAuthenticatorResponse);

void
WINAPI
EXPERIMENTAL_WebAuthNPluginFreeAddAuthenticatorResponse(
    _In_opt_ EXPERIMENTAL_PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE pPluginAddAuthenticatorResponse);

//
// Plugin Authenticator API: WebAuthNRemovePluginAuthenticator: Remove Plugin Authenticator
//

HRESULT
WINAPI
EXPERIMENTAL_WebAuthNPluginRemoveAuthenticator(
    _In_ LPCWSTR pwszPluginClsId);

//
// Plugin Authenticator API: WebAuthNPluginAuthenticatorUpdateDetails: Update Credential Metadata for Browser AutoFill Scenarios
//

typedef struct _EXPERIMENTAL_WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS {
    // Authenticator Name (Optional)
    LPCWSTR pwszAuthenticatorName;

    // Plugin COM ClsId
    LPCWSTR pwszPluginClsId;

    // Plugin COM New ClsId (Optional)
    LPCWSTR pwszNewPluginClsId;

    // Plugin Authenticator Logo for the Light themes. base64 svg (Optional)
    LPCWSTR pwszLightThemeLogo;

    // Plugin Authenticator Logo for the Dark themes. base64 svg (Optional)
    LPCWSTR pwszDarkThemeLogo;

    // CTAP CBOR encoded authenticatorGetInfo (Optional)
    DWORD cbAuthenticatorInfo;
    _Field_size_bytes_(cbAuthenticatorInfo)
    PBYTE pbAuthenticatorInfo;

} EXPERIMENTAL_WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS, *EXPERIMENTAL_PWEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS;
typedef const EXPERIMENTAL_WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS *EXPERIMENTAL_PCWEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS;

HRESULT
WINAPI
EXPERIMENTAL_WebAuthNPluginUpdateAuthenticatorDetails(
    _In_ EXPERIMENTAL_PCWEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS pPluginUpdateAuthenticatorDetails);


#endif //__midl

//
// Plugin Authenticator API: WebAuthNPluginAuthenticatorAddCredentials: Add Credential Metadata for Browser AutoFill Scenarios
//


typedef struct _EXPERIMENTAL_WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS {
    // Size of pbCredentialId.
    DWORD cbCredentialId;

    // Credential Identifier bytes. This field is required.
    #ifdef __midl
    [size_is(cbCredentialId)]
    #else
    _Field_size_bytes_(cbCredentialId)
    #endif
    PBYTE pbCredentialId;

    // Identifier for the RP. This field is required.
    PWSTR pwszRpId;

    // Contains the friendly name of the Relying Party, such as "Acme Corporation", "Widgets Inc" or "Awesome Site".
    // This field is required.
    PWSTR pwszRpName;

    // Identifier for the User. This field is required.
    DWORD cbUserId;

    // User Identifier bytes. This field is required.
    #ifdef __midl
    [size_is(cbUserId)]
    #else
    _Field_size_bytes_(cbUserId)
    #endif
    PBYTE pbUserId;

    // Contains a detailed name for this account, such as "john.p.smith@example.com".
    PWSTR pwszUserName;

    // For User: Contains the friendly name associated with the user account such as "John P. Smith".
    PWSTR pwszUserDisplayName;

} EXPERIMENTAL_WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS, *EXPERIMENTAL_PWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS;
typedef const EXPERIMENTAL_WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS *EXPERIMENTAL_PCWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS;

typedef struct _EXPERIMENTAL_WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS_LIST {
    // Plugin COM ClsId
    PWSTR pwszPluginClsId;

    // count of credentials
    DWORD cCredentialDetails;

    #ifdef __midl
    [size_is(cCredentialDetails)]
    #else
    _Field_size_(cCredentialDetails)
    #endif
    EXPERIMENTAL_PWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS *pCredentialDetails;

} EXPERIMENTAL_WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS_LIST, *EXPERIMENTAL_PWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS_LIST;
typedef const EXPERIMENTAL_WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS_LIST *EXPERIMENTAL_PCWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS_LIST;

#ifndef __midl

HRESULT
WINAPI
EXPERIMENTAL_WebAuthNPluginAuthenticatorAddCredentials(
    _In_ EXPERIMENTAL_PWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS_LIST pCredentialDetailsList);

//
// Plugin Authenticator API: WebAuthNPluginAuthenticatorRemoveCredentials: Remove Credential Metadata for Browser AutoFill Scenarios
//

HRESULT
WINAPI
EXPERIMENTAL_WebAuthNPluginAuthenticatorRemoveCredentials(
    _In_ EXPERIMENTAL_PWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS_LIST pCredentialDetailsList);

//
// Plugin Authenticator API: WebAuthNPluginAuthenticatorRemoveCredentials: Remove All Credential Metadata for Browser AutoFill Scenarios
//

HRESULT
WINAPI
EXPERIMENTAL_WebAuthNPluginAuthenticatorRemoveAllCredentials(
    _In_ LPCWSTR pwszPluginClsId);

//
// Plugin Authenticator API: WebAuthNPluginAuthenticatorGetAllCredentials: Get All Credential Metadata cached for Browser AutoFill Scenarios
//
HRESULT
WINAPI
EXPERIMENTAL_WebAuthNPluginAuthenticatorGetAllCredentials(
    _In_ LPCWSTR pwszPluginClsId,
    _Outptr_result_maybenull_ EXPERIMENTAL_PWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS_LIST *ppCredentialDetailsList);

//
// Hello UV API for Plugin: WebAuthNPluginPerformUv: Perform Hello UV related operations
//

typedef enum _EXPERIMENTAL_WEBAUTHN_PLUGIN_PERFORM_UV_OPERATION_TYPE
{
    PerformUv = 1,
    GetUvCount,
    GetPubKey
} EXPERIMENTAL_WEBAUTHN_PLUGIN_PERFORM_UV_OPERATION_TYPE;

typedef struct _EXPERIMENTAL_WEBAUTHN_PLUGIN_PERFORM_UV {
    HWND hwnd;
    GUID* transactionId;
    EXPERIMENTAL_WEBAUTHN_PLUGIN_PERFORM_UV_OPERATION_TYPE type;
    PCWSTR pwszUsername;
    PCWSTR pwszContext;
} EXPERIMENTAL_WEBAUTHN_PLUGIN_PERFORM_UV, *EXPERIMENTAL_PWEBAUTHN_PLUGIN_PERFROM_UV;
typedef const EXPERIMENTAL_WEBAUTHN_PLUGIN_PERFORM_UV *EXPERIMENTAL_PCWEBAUTHN_PLUGIN_PERFORM_UV;

typedef struct _EXPERIMENTAL_WEBAUTHN_PLUGIN_PERFORM_UV_RESPONSE {
    DWORD cbResponse;
    PBYTE pbResponse;
} EXPERIMENTAL_WEBAUTHN_PLUGIN_PERFORM_UV_RESPONSE, *EXPERIMENTAL_PWEBAUTHN_PLUGIN_PERFORM_UV_RESPONSE;
typedef const EXPERIMENTAL_WEBAUTHN_PLUGIN_PERFORM_UV_RESPONSE *EXPERIMENTAL_PCWEBAUTHN_PLUGIN_PERFORM_UV_RESPONSE;

HRESULT
WINAPI
EXPERIMENTAL_WebAuthNPluginPerformUv(
    _In_ EXPERIMENTAL_PCWEBAUTHN_PLUGIN_PERFORM_UV pPluginPerformUv,
    _Outptr_result_maybenull_ EXPERIMENTAL_PWEBAUTHN_PLUGIN_PERFORM_UV_RESPONSE *ppPluginPerformUvRespose);

void
WINAPI
EXPERIMENTAL_WebAuthNPluginFreePerformUvResponse(
    _In_opt_ EXPERIMENTAL_PWEBAUTHN_PLUGIN_PERFORM_UV_RESPONSE ppPluginPerformUvResponse);

#define EXPERIMENTAL_WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS_VERSION_1 1
#define EXPERIMENTAL_WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS_CURRENT_VERSION EXPERIMENTAL_WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS_VERSION_1
typedef struct _EXPERIMENTAL_WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS {
    //Version of this structure, to allow for modifications in the future.
    DWORD dwVersion;

    // Following have following values:
    //  +1 - TRUE
    //   0 - Not defined
    //  -1 - FALSE
    //up: "true" | "false"
    LONG lUp;
    //uv: "true" | "false"
    LONG lUv;
    //rk: "true" | "false"
    LONG lRequireResidentKey;
} EXPERIMENTAL_WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS, *EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS;
typedef const EXPERIMENTAL_WEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS *EXPERIMENTAL_PCWEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS;

#define EXPERIMENTAL_WEBAUTHN_CTAPCBOR_ECC_PUBLIC_KEY_VERSION_1 1
#define EXPERIMENTAL_WEBAUTHN_CTAPCBOR_ECC_PUBLIC_KEY_CURRENT_VERSION EXPERIMENTAL_WEBAUTHN_CTAPCBOR_ECC_PUBLIC_KEY_VERSION_1
typedef struct _EXPERIMENTAL_WEBAUTHN_CTAPCBOR_ECC_PUBLIC_KEY {
    //Version of this structure, to allow for modifications in the future.
    DWORD dwVersion;

    // Key type
    LONG lKty;

    // Hash Algorithm: ES256, ES384, ES512
    LONG lAlg;

    // Curve
    LONG lCrv;

    //Size of "x" (X Coordinate)
    DWORD cbX;

    //"x" (X Coordinate) data. Big Endian.
    PBYTE pbX;

    //Size of "y" (Y Coordinate)
    DWORD cbY;

    //"y" (Y Coordinate) data. Big Endian.
    PBYTE pbY;
} EXPERIMENTAL_WEBAUTHN_CTAPCBOR_ECC_PUBLIC_KEY, *EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_ECC_PUBLIC_KEY;
typedef const EXPERIMENTAL_WEBAUTHN_CTAPCBOR_ECC_PUBLIC_KEY *EXPERIMENTAL_PCWEBAUTHN_CTAPCBOR_ECC_PUBLIC_KEY;

#define EXPERIMENTAL_WEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION_VERSION_1 1
#define EXPERIMENTAL_WEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION_CURRENT_VERSION EXPERIMENTAL_WEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION_VERSION_1
typedef struct _EXPERIMENTAL_WEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION {
    //Version of this structure, to allow for modifications in the future.
    DWORD dwVersion;

    // Platform's key agreement public key
    EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_ECC_PUBLIC_KEY pKeyAgreement;

    DWORD cbEncryptedSalt;
    PBYTE pbEncryptedSalt;

    DWORD cbSaltAuth;
    PBYTE pbSaltAuth;
} EXPERIMENTAL_WEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION, *EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION;
typedef const EXPERIMENTAL_WEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION *EXPERIMENTAL_PCWEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION;

#define EXPERIMENTAL_WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST_VERSION_1 1
#define EXPERIMENTAL_WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST_CURRENT_VERSION EXPERIMENTAL_WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST_VERSION_1
typedef struct _EXPERIMENTAL_WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST {
    //Version of this structure, to allow for modifications in the future.
    DWORD dwVersion;
    
    //Input RP ID. Raw UTF8 bytes before conversion.
    //These are the bytes to be hashed in the Authenticator Data.
    DWORD cbRpId;
    PBYTE pbRpId;
    
    //Client Data Hash
    DWORD cbClientDataHash;
    PBYTE pbClientDataHash;
    
    //RP Information
    PCWEBAUTHN_RP_ENTITY_INFORMATION pRpInformation;
    
    //User Information
    PCWEBAUTHN_USER_ENTITY_INFORMATION pUserInformation;
    
    // Crypto Parameters
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS WebAuthNCredentialParameters;
    
    //Credentials used for exclusion
    WEBAUTHN_CREDENTIAL_LIST CredentialList;
    
    //Optional extensions to parse when performing the operation.
    DWORD cbCborExtensionsMap;
    PBYTE pbCborExtensionsMap;
    
    // Authenticator Options (Optional)
    EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS pAuthenticatorOptions;
    
    // Pin Auth (Optional)
    BOOL fEmptyPinAuth; // Zero length PinAuth is included in the request
    DWORD cbPinAuth;
    PBYTE pbPinAuth;
    
    //"hmac-secret": true extension
    LONG lHmacSecretExt;

    // "hmac-secret-mc" extension
    EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION pHmacSecretMcExtension;

    //"prf" extension
    LONG lPrfExt;
    DWORD cbHmacSecretSaltValues;
    PBYTE pbHmacSecretSaltValues;

    //"credProtect" extension. Nonzero if present
    DWORD dwCredProtect;

    // Nonzero if present
    DWORD dwPinProtocol;

    // Nonzero if present
    DWORD dwEnterpriseAttestation;

    //"credBlob" extension. Nonzero if present
    DWORD cbCredBlobExt;
    PBYTE pbCredBlobExt;

    //"largeBlobKey": true extension
    LONG lLargeBlobKeyExt;

    //"largeBlob": extension
    DWORD dwLargeBlobSupport;

    //"minPinLength": true extension
    LONG lMinPinLengthExt;

    // "json" extension. Nonzero if present
    DWORD cbJsonExt;
    PBYTE pbJsonExt;
} EXPERIMENTAL_WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST, *EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST;
typedef const EXPERIMENTAL_WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST *EXPERIMENTAL_PCWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST;

_Success_(return == S_OK)
HRESULT
WINAPI
EXPERIMENTAL_WebAuthNEncodeMakeCredentialResponse(
    _In_ PCWEBAUTHN_CREDENTIAL_ATTESTATION pCredentialAttestation,
    _Out_ DWORD *pcbResp,
    _Outptr_result_buffer_maybenull_(*pcbResp) BYTE **ppbResp
    );

_Success_(return == S_OK)
HRESULT
WINAPI
EXPERIMENTAL_WebAuthNDecodeMakeCredentialRequest(
    _In_ DWORD cbEncoded,
    _In_reads_bytes_(cbEncoded) const BYTE *pbEncoded,
    _Outptr_ EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST *ppMakeCredentialRequest
    );

void
WINAPI
EXPERIMENTAL_WebAuthNFreeDecodedMakeCredentialRequest(
    _In_opt_ EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST pMakeCredentialRequest
    );

#define EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST_VERSION_1 1
#define EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST_CURRENT_VERSION EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST_VERSION_1
typedef struct _EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST {
    //Version of this structure, to allow for modifications in the future.
    DWORD dwVersion;
    
    //RP ID. After UTF8 to Unicode conversion,
    PCWSTR pwszRpId;
    
    //Input RP ID. Raw UTF8 bytes before conversion.
    //These are the bytes to be hashed in the Authenticator Data.
    DWORD cbRpId;
    PBYTE pbRpId;
    
    //Client Data Hash
    DWORD cbClientDataHash;
    PBYTE pbClientDataHash;
    
    //Credentials used for inclusion
    WEBAUTHN_CREDENTIAL_LIST CredentialList;
    
    //Optional extensions to parse when performing the operation.
    DWORD cbCborExtensionsMap;
    PBYTE pbCborExtensionsMap;
    
    // Authenticator Options (Optional)
    EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_AUTHENTICATOR_OPTIONS pAuthenticatorOptions;
    
    // Pin Auth (Optional)
    BOOL fEmptyPinAuth; // Zero length PinAuth is included in the request
    DWORD cbPinAuth;
    PBYTE pbPinAuth;
    
    // HMAC Salt Extension (Optional)
    EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_HMAC_SALT_EXTENSION pHmacSaltExtension;

    // PRF Extension
    DWORD cbHmacSecretSaltValues;
    PBYTE pbHmacSecretSaltValues;

    DWORD dwPinProtocol;

    //"credBlob": true  extension
    LONG lCredBlobExt;

    //"largeBlobKey": true extension
    LONG lLargeBlobKeyExt;

    //"largeBlob" extension
    DWORD dwCredLargeBlobOperation;
    DWORD cbCredLargeBlobCompressed;
    PBYTE pbCredLargeBlobCompressed;
    DWORD dwCredLargeBlobOriginalSize;

    // "json" extension. Nonzero if present
    DWORD cbJsonExt;
    PBYTE pbJsonExt;
} EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST, *EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST;
typedef const EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST *EXPERIMENTAL_PCWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST;

_Success_(return == S_OK)
HRESULT
WINAPI
EXPERIMENTAL_WebAuthNDecodeGetAssertionRequest(
    _In_ DWORD cbEncoded,
    _In_reads_bytes_(cbEncoded) const BYTE *pbEncoded,
    _Outptr_ EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST *ppGetAssertionRequest
    );

void
WINAPI
EXPERIMENTAL_WebAuthNFreeDecodedGetAssertionRequest(
    _In_opt_ EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST pGetAssertionRequest
    );

typedef struct _EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE {
    // [1] credential (optional)
    // [2] authenticatorData
    // [3] signature
    WEBAUTHN_ASSERTION                      WebAuthNAssertion;
    
    // [4] user (optional)
    PCWEBAUTHN_USER_ENTITY_INFORMATION      pUserInformation;
    
    // [5] numberOfCredentials (optional)
    DWORD                                   dwNumberOfCredentials;
    
    // [6] userSelected (optional)
    LONG                                    lUserSelected;
    
    // [7] largeBlobKey (optional)
    DWORD                                   cbLargeBlobKey;
    PBYTE                                   pbLargeBlobKey;
    
    // [8] unsignedExtensionOutputs
    DWORD                                   cbUnsignedExtensionOutputs;
    PBYTE                                   pbUnsignedExtensionOutputs;
} EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE, *EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE;
typedef const EXPERIMENTAL_PWEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE *EXPERIMENTAL_PCWEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE;

_Success_(return == S_OK)
HRESULT
WINAPI
EXPERIMENTAL_WebAuthNEncodeGetAssertionResponse(
    _In_ EXPERIMENTAL_PCWEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE pGetAssertionResponse,
    _Out_ DWORD *pcbResp,
    _Outptr_result_buffer_maybenull_(*pcbResp) BYTE **ppbResp
    );

#endif //__midl



#ifdef __cplusplus
}       // Balance extern "C" above
#endif

#endif // WINAPI_FAMILY_PARTITION
#pragma endregion

#endif // __PLUGIN_AUTHENTICATOR_MGMT_H_