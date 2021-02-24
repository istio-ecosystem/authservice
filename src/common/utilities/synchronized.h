#ifndef AUTHSERVICE_SYNCHRONIZED_H
#define AUTHSERVICE_SYNCHRONIZED_H

#include <mutex>
#define synchronized(m) \
  for (std::unique_lock<std::recursive_mutex> lk(m); lk; lk.unlock())

#endif  // AUTHSERVICE_SYNCHRONIZED_H
