/*
** Project LibCppSockets, 2026
**
** Author Francois Michaut
**
** Started on  Wed Jul  1 14:14:07 2026 Francois Michaut
** Last update Thu Jul  2 03:00:44 2026 Francois Michaut
**
** TestOpensslWrappers.cpp : OpenSSL wrappers tests
*/

#include "CppSockets/Tls/Certificate.hpp"

#include <cassert>
#include <filesystem>
#include <stdexcept>

const std::u8string ORG_NAME = u8"test1";
const std::u8string ORG_UNIT_NAME = u8"test2";
const std::u8string USER_ID = u8"user_test";
const std::u8string COMMON_NAME = u8"CommonName";
const std::u8string DN_QUAL = u8"DN Qual";

void TestCertificateCreate(const std::filesystem::path &cert_path) {
    CppSockets::EVP_PKEY_ptr pkey {EVP_RSA_gen(4096)}; // NOLINT(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
    CppSockets::x509Certificate cert;
    CppSockets::x509Name subject;

    cert.set_public_key(pkey);

    cert.set_not_before(0, 0);
    cert.set_not_after(365, 0);

    // NOLINTBEGIN(hicpp-signed-bitwise)
    subject.add_entry(NID_organizationName, MBSTRING_ASC, ORG_NAME);
    subject.add_entry(NID_organizationalUnitName, MBSTRING_ASC, ORG_UNIT_NAME);
    subject.add_entry(NID_userId, MBSTRING_ASC, USER_ID);

    subject.add_entry(NID_commonName, MBSTRING_ASC, COMMON_NAME);
    subject.add_entry(NID_dnQualifier, MBSTRING_ASC, DN_QUAL);
    // NOLINTEND(hicpp-signed-bitwise)

    cert.set_self_signed_name(subject);
    cert.sign(pkey);

    cert.save(cert_path);
}

void TestCertificateLoad(const std::filesystem::path &cert_path) {
    CppSockets::x509Certificate cert;

    cert.load(cert_path);
    CppSockets::x509Name subject = cert.get_subject_name();
    CppSockets::x509NameEntry org_name = subject.get_entry(NID_organizationName);
    CppSockets::x509NameEntry org_unit_name = subject.get_entry(NID_organizationalUnitName);
    CppSockets::x509NameEntry user_id = subject.get_entry(NID_userId);
    CppSockets::x509NameEntry common_name = subject.get_entry(NID_commonName);
    CppSockets::x509NameEntry dn_qual = subject.get_entry(NID_dnQualifier);

    const ASN1_STRING *org_name_str = org_name.get_data();
    const ASN1_STRING *org_unit_name_str = org_unit_name.get_data();
    const ASN1_STRING *user_id_str = user_id.get_data();
    const ASN1_STRING *common_name_str = common_name.get_data();
    const ASN1_STRING *dn_qual_str = dn_qual.get_data();

    const auto *org_name_data = reinterpret_cast<const char8_t *>(
        ASN1_STRING_get0_data(org_name_str)
    );
    const auto *org_unit_name_data = reinterpret_cast<const char8_t *>(
        ASN1_STRING_get0_data(org_unit_name_str)
    );
    const auto *user_id_data = reinterpret_cast<const char8_t *>(
        ASN1_STRING_get0_data(user_id_str)
    );
    const auto *common_name_data = reinterpret_cast<const char8_t *>(
        ASN1_STRING_get0_data(common_name_str)
    );
    const auto *dn_qual_data = reinterpret_cast<const char8_t *>(
        ASN1_STRING_get0_data(dn_qual_str)
    );

    std::basic_string_view<char8_t> org_name_view {
        org_name_data, static_cast<std::size_t>(ASN1_STRING_length(org_name_str))
    };
    std::basic_string_view<char8_t> org_unit_name_view {
        org_unit_name_data, static_cast<std::size_t>(ASN1_STRING_length(org_unit_name_str))
    };
    std::basic_string_view<char8_t> user_id_view {
        user_id_data, static_cast<std::size_t>(ASN1_STRING_length(user_id_str))
    };
    std::basic_string_view<char8_t> common_name_view {
        common_name_data, static_cast<std::size_t>(ASN1_STRING_length(common_name_str))
    };
    std::basic_string_view<char8_t> dn_qual_view {
        dn_qual_data, static_cast<std::size_t>(ASN1_STRING_length(dn_qual_str))
    };

    assert(ORG_NAME == org_name_view);
    assert(ORG_UNIT_NAME == org_unit_name_view);
    assert(USER_ID == user_id_view);
    assert(COMMON_NAME == common_name_view);
    assert(DN_QUAL == dn_qual_view);
}

auto Tls_TestOpensslWrappers(int /* ac  */, char ** const /* argv */) -> int {
    std::filesystem::path cert_path = std::filesystem::temp_directory_path() / "test_cppsockets___random_file_name";

    TestCertificateCreate(cert_path);
    TestCertificateLoad(cert_path);
    std::filesystem::remove(cert_path);
    return 0;
}
