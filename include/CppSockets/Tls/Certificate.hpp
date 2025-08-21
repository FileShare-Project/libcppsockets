/*
** Project LibCppSockets, 2025
**
** Author Francois Michaut
**
** Started on  Fri Aug  1 09:50:33 2025 Francois Michaut
** Last update Wed Aug 20 17:17:44 2025 Francois Michaut
**
** Certificate.hpp : Classes to create and manage Certificates
*/

#pragma once

#include "CppSockets/Tls/Utils.hpp"

#include <openssl/crypto.h>

#include <cstdint>
#include <filesystem>

// TODO: Add weak ptr equivalent instead of `bool own = false`
namespace CppSockets {
    class x509NameEntry;

    class x509Name {
        public:
            x509Name();
            x509Name(X509_NAME_ptr ptr);
            x509Name(X509_NAME *ptr, bool own = true);

            x509Name(const x509Name &other) { *this = other; }
            x509Name(x509Name &&other) noexcept = default;
            auto operator=(const x509Name &other) -> x509Name &;
            auto operator=(x509Name &&other) noexcept -> x509Name & = default;

            ~x509Name();

            [[nodiscard]] auto clone() const -> x509Name { return {*this}; }

            void add_entry(const x509NameEntry &entry, int loc = -1, int set = 0);
            void add_entry(const std::string &field_name, int type, const std::u8string &data, int loc = -1, int set = 0);
            void add_entry(const ASN1_OBJECT *obj, int type, const std::u8string &data, int loc = -1, int set = 0);
            void add_entry(int nid, int type, const std::u8string &data, int loc = -1, int set = 0);

            [[nodiscard]] auto entry_count() const -> int;
            [[nodiscard]] auto get_entry_by_index(int idx) const -> x509NameEntry;
            [[nodiscard]] auto get_entry(int nid, int lastpos = -1) const -> x509NameEntry;
            [[nodiscard]] auto get_entry(const ASN1_OBJECT *obj, int lastpos = -1) const -> x509NameEntry;
            auto delete_entry(int loc) -> x509NameEntry;

            [[nodiscard]] auto get_index(int nid, int lastpos = -1) const -> int;
            [[nodiscard]] auto get_index(const ASN1_OBJECT *obj, int lastpos = -1) const -> int;

            // TODO ?
            // X509_NAME_get0_der
            // X509_NAME_cmp
            // X509_NAME_digest
            // X509_NAME_hash
            // X509_NAME_hash_ex
            // X509_NAME_oneline
            // X509_NAME_print
            // X509_NAME_print_ex
            // X509_NAME_print_ex_fp

            [[nodiscard]] auto get() const -> X509_NAME * { return m_ptr.get(); }
        private:
            X509_NAME_ptr m_ptr;
            bool m_own = true;
    };

    class x509NameEntry {
        public:
            x509NameEntry();
            x509NameEntry(X509_NAME_ENTRY_ptr ptr);
            x509NameEntry(X509_NAME_ENTRY *ptr, bool own = true);
            x509NameEntry(const std::string &name, int type, const std::u8string &data);
            x509NameEntry(const ASN1_OBJECT *obj, int type, const std::u8string &data);
            x509NameEntry(int nid, int type, const std::u8string &data);

            x509NameEntry(const x509NameEntry &other) { *this = other; }
            x509NameEntry(x509NameEntry &&other) noexcept = default;
            auto operator=(const x509NameEntry &other) -> x509NameEntry &;
            auto operator=(x509NameEntry &&other) noexcept -> x509NameEntry & = default;

            ~x509NameEntry();

            [[nodiscard]] auto clone() const -> x509NameEntry { return {*this}; }

            void set_object(const ASN1_OBJECT *obj);
            void set_data(int type, const std::u8string &data);

            [[nodiscard]] auto get_object() const -> const ASN1_OBJECT *;
            [[nodiscard]] auto get_data() const -> const ASN1_STRING *;

            [[nodiscard]] auto get() const -> X509_NAME_ENTRY * { return m_ptr.get(); }
        private:
            X509_NAME_ENTRY_ptr m_ptr;
            bool m_own = true;
    };

    class x509Extension {
        public:
            x509Extension();
            x509Extension(X509_EXTENSION_ptr ptr);
            x509Extension(X509_EXTENSION *ptr, bool own = true);
            x509Extension(int nid, int crit, ASN1_OCTET_STRING *data);
            x509Extension(const ASN1_OBJECT *obj, int crit, ASN1_OCTET_STRING *data);

            x509Extension(const x509Extension &other) { *this = other; }
            x509Extension(x509Extension &&other) noexcept = default;
            auto operator=(const x509Extension &other) -> x509Extension &;
            auto operator=(x509Extension &&other) noexcept -> x509Extension & = default;

            ~x509Extension();

            [[nodiscard]] auto clone() const -> x509Extension { return {*this}; }

            void set_data(ASN1_OCTET_STRING *data);
            void set_object(const ASN1_OBJECT *obj);
            void set_critical(bool crit);

            [[nodiscard]] auto get_data() const -> ASN1_OCTET_STRING *;
            [[nodiscard]] auto get_object() const -> ASN1_OBJECT *;
            [[nodiscard]] auto get_critical() const -> bool;

            [[nodiscard]] auto get() const -> X509_EXTENSION * { return m_ptr.get(); }
        private:
            X509_EXTENSION_ptr m_ptr;
            bool m_own = true;
    };

    class x509Certificate {
        public:
            x509Certificate();
            x509Certificate(X509_ptr ptr);
            x509Certificate(X509 *ptr, bool own = true);
            explicit x509Certificate(const std::filesystem::path &pem_file_path);

            x509Certificate(const x509Certificate &other) { *this = other; }
            x509Certificate(x509Certificate &&other) noexcept = default;
            auto operator=(const x509Certificate &other) -> x509Certificate &;
            auto operator=(x509Certificate &&other) noexcept -> x509Certificate & = default;

            ~x509Certificate();

            [[nodiscard]] auto clone() const -> x509Certificate { return {*this}; }

            // TODO: Provide overloads for password protected certs
            void load(const std::filesystem::path &pem_file_path);
            void save(const std::filesystem::path &pem_file_path) const;

            // TODO: Provide overloads for hardcoded time
            void set_not_before(int offset_day, std::int64_t offset_sec, time_t *in_tm = nullptr);
            void set_not_after(int offset_day, std::int64_t offset_sec, time_t *in_tm = nullptr);
            [[nodiscard]] auto get_not_before() const -> const ASN1_TIME *;
            [[nodiscard]] auto get_not_after() const -> const ASN1_TIME *;

            void set_version(std::int64_t version);
            [[nodiscard]] auto get_version() const -> std::int64_t;

            void set_serial_number(std::uint64_t serial_number);
            void set_serial_number(BIGNUM *serial_number);
            [[nodiscard]] auto get_serial_number() const -> ASN1_INTEGER *;

            void set_public_key(const EVP_PKEY_ptr &pkey);
            [[nodiscard]] auto get_pubkey() const -> const EVP_PKEY *;

            void set_subject_name(const x509Name &name);
            void set_issuer_name(const x509Name &name);
            void set_self_signed_name(const x509Name &name);
            [[nodiscard]] auto get_issuer_name() const -> x509Name;
            [[nodiscard]] auto get_subject_name() const -> x509Name;

            void add_extension(const x509Extension &ext, int loc = -1);
            auto delete_extension(int loc) -> x509Extension;
            [[nodiscard]] auto extension_count() const -> int;

            [[nodiscard]] auto get_extension(std::uint32_t loc) const -> x509Extension;
            [[nodiscard]] auto get_extension_by(int nid, int lastpos = - 1) const -> x509Extension;
            [[nodiscard]] auto get_extension_by(const ASN1_OBJECT *obj, int lastpos = -1) const -> x509Extension;
            [[nodiscard]] auto get_extension_by(bool critical, int lastpos = - 1) const -> x509Extension;

            [[nodiscard]] auto self_signed(bool verify_signature) const -> bool;
            [[nodiscard]] auto verify(const EVP_PKEY_ptr &pkey) const -> bool;
            [[nodiscard]] auto verify() const -> bool;

            void sign(const EVP_PKEY_ptr &pkey, const EVP_MD *digest = EVP_sha256());

            [[nodiscard]] auto get() const -> X509 * { return m_ptr.get(); }
        private:
            X509_ptr m_ptr;
            bool m_own = true;
    };

    using Certificate = x509Certificate;
}
