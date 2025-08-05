/*
** Project LibCppSockets, 2025
**
** Author Francois Michaut
**
** Started on  Sat Aug  2 22:41:35 2025 Francois Michaut
** Last update Tue Aug  5 13:08:40 2025 Francois Michaut
**
** Certificate.cpp : Implementation of classes to create and manage Certificates
*/

#include "CppSockets/Certificate.hpp"
#include "CppSockets/SSL_Utils.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdexcept>

#define REQUIRED_PTR(ptr, name)                                                \
  if (!ptr) {                                                                  \
    throw std::runtime_error("Failed to create " name);                        \
  }

#define ASSIGNMENT_OPERATOR(type)                                              \
    if (this == &other) {                                                      \
        return *this;                                                          \
    }                                                                          \
                                                                               \
    type *dup = type##_dup(other.m_ptr.get());                                 \
                                                                               \
    if (dup == nullptr) {                                                      \
        throw std::runtime_error("Failed to dup ##type##");                    \
    }                                                                          \
    this->m_ptr.reset(dup);                                                    \
    return *this;                                                              \

namespace {
    template<typename Dst, typename Src>
    inline auto numeric_cast(const Src value) -> Dst {
        const Dst result = static_cast<Dst>(value);

        if (result != value) {
            throw std::overflow_error("Overflow/Underflow error");
        }
        return result;
    }
}

// x509Name
namespace CppSockets {
    x509Name::x509Name() :
        m_ptr(X509_NAME_new())
    {
        REQUIRED_PTR(m_ptr, "X509_NAME")
    }

    x509Name::x509Name(X509_NAME_ptr ptr) :
        m_ptr(std::move(ptr))
    {
        REQUIRED_PTR(m_ptr, "X509_NAME")
    }

    auto x509Name::operator=(const x509Name &other) -> x509Name & {
        ASSIGNMENT_OPERATOR(X509_NAME)
    }

    void x509Name::add_entry(const x509NameEntry &entry, int loc, int set) {
        auto ret = X509_NAME_add_entry(m_ptr.get(), entry.get(), loc, set);

        check_or_throw_openssl_error(ret);
    }

    void x509Name::add_entry(const std::string &field_name, int type, const std::u8string &data, int loc, int set) {
        auto ret = X509_NAME_add_entry_by_txt(m_ptr.get(), field_name.c_str(), type, data.c_str(), numeric_cast<int>(data.size()), loc, set);

        check_or_throw_openssl_error(ret);
    }

    void x509Name::add_entry(const ASN1_OBJECT *obj, int type, const std::u8string &data, int loc, int set) {
        auto ret = X509_NAME_add_entry_by_OBJ(m_ptr.get(), obj, type, data.c_str(), numeric_cast<int>(data.size()), loc, set);

        check_or_throw_openssl_error(ret);
    }

    void x509Name::add_entry(int nid, int type, const std::u8string &data, int loc, int set) {
        auto ret = X509_NAME_add_entry_by_NID(m_ptr.get(), nid, type, data.c_str(), numeric_cast<int>(data.size()), loc, set);

        check_or_throw_openssl_error(ret);
    }

    auto x509Name::entry_count() const -> int {
        return X509_NAME_entry_count(m_ptr.get());
    }

    auto x509Name::get_entry(int loc) const -> x509NameEntry {
        X509_NAME_ENTRY_ptr ptr{check_or_throw_openssl_error(X509_NAME_get_entry(m_ptr.get(), loc))};

        return {std::move(ptr)};
    }

    auto x509Name::delete_entry(int loc) -> x509NameEntry {
        X509_NAME_ENTRY_ptr ptr{check_or_throw_openssl_error(X509_NAME_delete_entry(m_ptr.get(), loc))};

        return {std::move(ptr)};
    }

    auto x509Name::get_index(int nid, int lastpos) const -> int {
        return X509_NAME_get_index_by_NID(m_ptr.get(), nid, lastpos);
    }

    auto x509Name::get_index(const ASN1_OBJECT *obj, int lastpos) const -> int {
        return X509_NAME_get_index_by_OBJ(m_ptr.get(), obj, lastpos);
    }
}

// x509NameEntry
namespace CppSockets {
    x509NameEntry::x509NameEntry() :
        m_ptr(X509_NAME_ENTRY_new())
    {
        REQUIRED_PTR(m_ptr, "X509_NAME_ENTRY")
    }

    x509NameEntry::x509NameEntry(X509_NAME_ENTRY_ptr ptr) :
        m_ptr(std::move(ptr))
    {
        REQUIRED_PTR(m_ptr, "X509_NAME_ENTRY")
    }

    x509NameEntry::x509NameEntry(const std::string &name, int type, const std::u8string &data) :
        m_ptr(X509_NAME_ENTRY_create_by_txt(nullptr, name.c_str(), type, data.c_str(), numeric_cast<int>(data.size())))
    {
        REQUIRED_PTR(m_ptr, "X509_NAME_ENTRY")
    }

    x509NameEntry::x509NameEntry(const ASN1_OBJECT *obj, int type, const std::u8string &data) :
        m_ptr(X509_NAME_ENTRY_create_by_OBJ(nullptr, obj, type, data.c_str(), numeric_cast<int>(data.size())))
    {
        REQUIRED_PTR(m_ptr, "X509_NAME_ENTRY")
    }

    x509NameEntry::x509NameEntry(int nid, int type, const std::u8string &data) :
        m_ptr(X509_NAME_ENTRY_create_by_NID(nullptr, nid, type, data.c_str(), numeric_cast<int>(data.size())))
    {
        REQUIRED_PTR(m_ptr, "X509_NAME_ENTRY")
    }

    auto x509NameEntry::operator=(const x509NameEntry &other) -> x509NameEntry & {
        ASSIGNMENT_OPERATOR(X509_NAME_ENTRY)
    }

    void x509NameEntry::set_object(const ASN1_OBJECT *obj) {
        auto ret = X509_NAME_ENTRY_set_object(m_ptr.get(), obj);

        check_or_throw_openssl_error(ret);
    }

    void x509NameEntry::set_data(int type, const std::u8string &data) {
        auto ret = X509_NAME_ENTRY_set_data(m_ptr.get(), type, data.c_str(), numeric_cast<int>(data.size()));

        check_or_throw_openssl_error(ret);
    }

    auto x509NameEntry::get_object() const -> ASN1_OBJECT * {
        return check_or_throw_openssl_error(X509_NAME_ENTRY_get_object(m_ptr.get()));
    }

    auto x509NameEntry::get_data() const -> ASN1_STRING * {
        return check_or_throw_openssl_error(X509_NAME_ENTRY_get_data(m_ptr.get()));
    }
}

// x509Extension
namespace CppSockets {
    x509Extension::x509Extension() :
        m_ptr(X509_EXTENSION_new())
    {
        REQUIRED_PTR(m_ptr, "X509_EXTENSION")
    }

    x509Extension::x509Extension(X509_EXTENSION_ptr ptr) :
        m_ptr(std::move(ptr))
    {
        REQUIRED_PTR(m_ptr, "X509_EXTENSION")
    }

    x509Extension::x509Extension(int nid, int crit, ASN1_OCTET_STRING *data) :
        m_ptr(X509_EXTENSION_create_by_NID(nullptr, nid, crit, data))
    {
        REQUIRED_PTR(m_ptr, "X509_EXTENSION")
    }

    x509Extension::x509Extension(const ASN1_OBJECT *obj, int crit, ASN1_OCTET_STRING *data) :
        m_ptr(X509_EXTENSION_create_by_OBJ(nullptr, obj, crit, data))
    {
        REQUIRED_PTR(m_ptr, "X509_EXTENSION")
    }

    auto x509Extension::operator=(const x509Extension &other) -> x509Extension & {
        ASSIGNMENT_OPERATOR(X509_EXTENSION)
    }

    void x509Extension::set_data(ASN1_OCTET_STRING *data) {
        check_or_throw_openssl_error(X509_EXTENSION_set_data(m_ptr.get(), data));
    }

    void x509Extension::set_object(const ASN1_OBJECT *obj) {
        check_or_throw_openssl_error(X509_EXTENSION_set_object(m_ptr.get(), obj));
    }

    void x509Extension::set_critical(bool crit) {
        check_or_throw_openssl_error(X509_EXTENSION_set_critical(m_ptr.get(), crit));
    }

    auto x509Extension::get_data() const -> ASN1_OCTET_STRING * {
        return X509_EXTENSION_get_data(m_ptr.get());
    }

    auto x509Extension::get_object() const -> ASN1_OBJECT * {
        return X509_EXTENSION_get_object(m_ptr.get());
    }

    auto x509Extension::get_critical() const -> bool {
        return X509_EXTENSION_get_critical(m_ptr.get()) == 1;
    }
}

// x509Certificate
namespace CppSockets {
    x509Certificate::x509Certificate() :
        m_ptr(X509_new())
    {
        REQUIRED_PTR(m_ptr, "X509")
    }

    x509Certificate::x509Certificate(X509_ptr x509) :
        m_ptr(std::move(x509))
    {
        REQUIRED_PTR(m_ptr, "X509")
    }

    x509Certificate::x509Certificate(const std::filesystem::path &pem_file_path) {
        load(pem_file_path);
    }

    auto x509Certificate::operator=(const x509Certificate &other) -> x509Certificate & {
        ASSIGNMENT_OPERATOR(X509)
    }

    void x509Certificate::load(const std::filesystem::path &pem_file_path) {
        BIO_ptr bio(BIO_new_file(pem_file_path.string().c_str(), "r"));

        if (!bio) {
            throw std::runtime_error("Failed to open file");
        }
        auto *x509 = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);

        if (!x509) {
            throw std::runtime_error("Failed to load X509 Certificate");
        }
        m_ptr.reset(x509);
    }

    void x509Certificate::save(const std::filesystem::path &pem_file_path) const {
        BIO_ptr bio(BIO_new_file(pem_file_path.string().c_str(), "w"));

        if (!bio) {
            throw std::runtime_error("Failed to open file");
        }
        if (PEM_write_bio_X509(bio.get(), m_ptr.get()) < 1) {
            throw std::runtime_error("Failed to save X509 Certificate");
        }
    }

    void x509Certificate::set_not_before(int offset_day, std::int64_t offset_sec, time_t *in_tm) {
        ASN1_TIME *not_before = X509_getm_notBefore(m_ptr.get());

        if (!X509_time_adj_ex(not_before, offset_day, offset_sec, in_tm)) {
            throw std::runtime_error("Failed to adjust not_before time");
        }
    }

    void x509Certificate::set_not_after(int offset_day, std::int64_t offset_sec, time_t *in_tm) {
        ASN1_TIME *not_after = X509_getm_notAfter(m_ptr.get());

        if (!X509_time_adj_ex(not_after, offset_day, offset_sec, in_tm)) {
            throw std::runtime_error("Failed to adjust not_after time");
        }
    }


    void x509Certificate::set_version(std::int64_t version) {
        if (!X509_set_version(m_ptr.get(), version)) {
            throw std::runtime_error("Failed to set version");
        }
    }

    auto x509Certificate::get_version() const -> std::int64_t {
        return X509_get_version(m_ptr.get());
    }

    void x509Certificate::set_serial_number(int64_t serial_number) {
        ASN1_INTEGER *ptr = X509_get_serialNumber(m_ptr.get());

        if (!ASN1_INTEGER_set_int64(ptr, serial_number)) {
            throw std::runtime_error("Failed to set serial number");
        }
    }

    void x509Certificate::set_serial_number(uint64_t serial_number) {
        ASN1_INTEGER *ptr = X509_get_serialNumber(m_ptr.get());

        if (!ASN1_INTEGER_set_uint64(ptr, serial_number)) {
            throw std::runtime_error("Failed to set serial number");
        }
    }

    void x509Certificate::set_serial_number(BIGNUM *serial_number) {
        ASN1_INTEGER *ptr = X509_get_serialNumber(m_ptr.get());

        if (!BN_to_ASN1_INTEGER(serial_number, ptr)) {
            throw std::runtime_error("Failed to set serial number");
        }
    }

    void x509Certificate::set_public_key(const EVP_PKEY_ptr &pkey) {
        if (!X509_set_pubkey(m_ptr.get(), pkey.get())) {
            throw std::runtime_error("Failed to set public key");
        }
    }

    void x509Certificate::set_subject_name(const x509Name &name) {
        if (!X509_set_subject_name(m_ptr.get(), name.get())) {
            throw std::runtime_error("Failed to set subject name");
        }
    }

    void x509Certificate::set_issuer_name(const x509Name &name) {
        if (!X509_set_issuer_name(m_ptr.get(), name.get())) {
            throw std::runtime_error("Failed to set issuer name");
        }
    }

    void x509Certificate::set_self_signed_name(const x509Name &name) {
        set_issuer_name(name);
        set_subject_name(name);
    }

    void x509Certificate::add_extension(const x509Extension &ext, int loc) {
        if (!X509_add_ext(m_ptr.get(), ext.get(), loc)) {
            throw std::runtime_error("Failed to add extension");
        }
    }

    auto x509Certificate::delete_extension(int loc) -> x509Extension {
        X509_EXTENSION_ptr ptr {X509_delete_ext(m_ptr.get(), loc)};

        if (!ptr) {
            throw std::runtime_error("Failed to delete extension");
        }
        return {std::move(ptr)};
    }

    auto x509Certificate::extension_count() const -> int {
        return X509_get_ext_count(m_ptr.get());
    }

    auto x509Certificate::get_extension(std::uint32_t loc) const -> x509Extension {
        X509_EXTENSION_ptr ptr {X509_get_ext(m_ptr.get(), numeric_cast<int>(loc))};

        if (!ptr) {
            throw std::runtime_error("Failed to get extension");
        }
        return {std::move(ptr)};
    }

    auto x509Certificate::get_extension_by(int nid, int lastpos) const -> x509Extension {
        int idx = X509_get_ext_by_NID(m_ptr.get(), nid, lastpos);

        if (idx < 0) {
            throw std::runtime_error("Failed to get extension");
        }
        return get_extension(idx);
    }

    auto x509Certificate::get_extension_by(const ASN1_OBJECT *obj, int lastpos) const -> x509Extension {
        int idx = X509_get_ext_by_OBJ(m_ptr.get(), obj, lastpos);

        if (idx < 0) {
            throw std::runtime_error("Failed to get extension");
        }
        return get_extension(idx);
    }

    auto x509Certificate::get_extension_by(bool critical, int lastpos) const -> x509Extension {
        int idx = X509_get_ext_by_critical(m_ptr.get(), critical, lastpos);

        if (idx < 0) {
            throw std::runtime_error("Failed to get extension");
        }
        return get_extension(idx);
    }

    auto x509Certificate::self_signed(bool verify_signature) const -> bool {
        auto ret = X509_self_signed(m_ptr.get(), verify_signature);

        if (ret < 0) {
            throw std::runtime_error("Failed to check certificate self-signed");
        }
        return ret;
    }

    auto x509Certificate::verify(const EVP_PKEY_ptr &pkey) const -> bool {
        auto ret = X509_verify(m_ptr.get(), pkey.get());

        if (ret < 0) {
            throw std::runtime_error("Failed to check certificate signature");
        }
        return ret;
    }

    void x509Certificate::sign(const EVP_PKEY_ptr &pkey, const EVP_MD *digest) {
        auto ret = X509_sign(m_ptr.get(), pkey.get(), digest);

        if (ret < 0) {
            throw std::runtime_error("Failed to sign certificate");
        }
    }
}
