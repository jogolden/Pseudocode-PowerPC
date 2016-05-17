// Originally created by Youness Alaoui
// Pseudo code generation by imGol2den

#pragma once

#include "ida.hpp"

int parse_instruction(ea_t ea, strvec_t *sv);
int parse_function(ea_t ea, strvec_t *sv);
int parse_current_function(strvec_t *sv);