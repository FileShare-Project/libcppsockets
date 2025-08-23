/*
** Project LibCppSockets, 2025
**
** Author Francois Michaut
**
** Started on  Wed Aug 20 16:54:02 2025 Francois Michaut
** Last update Fri Aug 22 21:46:55 2025 Francois Michaut
**
** SslMacros.hpp : Private Macros to define SSL wrappers
*/

#define REQUIRED_PTR(ptr, name)                                                                     \
  if (!ptr) {                                                                                       \
    throw std::runtime_error("Failed to create " name);                                             \
  }

#define ASSIGNMENT_OPERATOR(type)                                                                   \
    if (this == &other) {                                                                           \
        return *this;                                                                               \
    }                                                                                               \
                                                                                                    \
    type *dup = type##_dup(other.m_ptr.get());                                                      \
                                                                                                    \
    if (dup == nullptr) {                                                                           \
        throw std::runtime_error("Failed to dup " #type);                                          \
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
    if (!this->m_own) {                                                                             \
        (void)this->m_ptr.release();                                                                \
    }                                                                                               \
    this->m_ptr.reset(other.m_ptr.get());                                                           \
    this->m_own = false;                                                                            \
    return *this;                                                                                   \

#define MAKE_DESTRUCTOR(klass)                                                                      \
    klass::~klass() {                                                                               \
        if (!m_own) {                                                                               \
            (void)m_ptr.release();                                                                  \
        }                                                                                           \
    }
