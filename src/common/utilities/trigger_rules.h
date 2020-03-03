#ifndef AUTHSERVICE_TRIGGER_RULES_H
#define AUTHSERVICE_TRIGGER_RULES_H

#include "config/config.pb.h"
#include "absl/strings/string_view.h"

namespace authservice {
namespace common {
namespace utilities {
namespace trigger_rules {

bool TriggerRuleMatchesPath(
    absl::string_view path,
    const google::protobuf::RepeatedPtrField<config::TriggerRule> &trigger_rules_config);

bool MatchString(absl::string_view str, const config::StringMatch& match);

} // namespace trigger_rules
} // namespace utilities
} // namespace common
} // namespace authservice

#endif //AUTHSERVICE_TRIGGER_RULES_H
