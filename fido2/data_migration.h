// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#ifndef FIDO2_PR_DATA_MIGRATION_H
#define FIDO2_PR_DATA_MIGRATION_H

#include "storage.h"

void do_migration_if_required(AuthenticatorState* state_current);

#endif //FIDO2_PR_DATA_MIGRATION_H
