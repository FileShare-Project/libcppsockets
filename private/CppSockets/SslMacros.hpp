/*
** Project LibCppSockets, 2025
**
** Author Francois Michaut
**
** Started on  Wed Aug 20 16:54:02 2025 Francois Michaut
** Last update Thu Jul  2 03:01:00 2026 Francois Michaut
**
** SslMacros.hpp : Private Macros to define SSL wrappers
*/

#define REQUIRED_PTR(ptr, name)                                                                     \
  if (!ptr) {                                                                                       \
    throw std::runtime_error("Failed to create " name);                                             \
  }                                                                                                 \

#define ASSIGNMENT_OPERATOR(type)                                                                   \
    if (this == &other) {                                                                           \
        return *this;                                                                               \
    }                                                                                               \
                                                                                                    \
    type *ptr = other.m_ptr.get();                                                                  \
    type *dup = type##_dup(ptr);                                                                    \
                                                                                                    \
    if (ptr != nullptr && dup == nullptr) {                                                         \
        throw std::runtime_error("Failed to dup " #type);                                           \
    }                                                                                               \
    if (!this->m_own) {                                                                             \
        (void)this->m_ptr.release();                                                                \
    }                                                                                               \
    this->m_ptr.reset(dup);                                                                         \
    this->m_own = true;                                                                             \
    return *this;                                                                                   \

#define UP_REF_ASSIGNMENT_OPERATOR(type)                                                            \
    if (this == &other) {                                                                           \
        return *this;                                                                               \
    }                                                                                               \
                                                                                                    \
    type *ptr = other.m_ptr.get();                                                                  \
                                                                                                    \
    if (ptr) {                                                                                      \
        if (!SSL_CTX_up_ref(ptr)) {                                                                 \
            throw std::runtime_error("Failed to up ref " #type);                                    \
        }                                                                                           \
    }                                                                                               \
    if (!this->m_own) {                                                                             \
        (void)this->m_ptr.release();                                                                \
    }                                                                                               \
    this->m_ptr.reset(ptr);                                                                         \
    this->m_own = true;                                                                             \
    return *this;                                                                                   \

#define MAKE_DESTRUCTOR(klass)                                                                      \
    klass::~klass() {                                                                               \
        if (!m_own) {                                                                               \
            (void)m_ptr.release();                                                                  \
        }                                                                                           \
    }
