/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common.h"

#include "py/runtime.h"

#include TREZOR_BOARD

// #if MICROPY_PY_TREZORMINTLAYER

#include "modtrezormintlayer-utils.h"

STATIC const mp_rom_map_elem_t mp_module_trezormintlayer_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_trezormintlayer)},
    {MP_ROM_QSTR(MP_QSTR_utils), MP_ROM_PTR(&mod_trezormintlayer_utils_module)},
};
STATIC MP_DEFINE_CONST_DICT(mp_module_trezormintlayer_globals,
                            mp_module_trezormintlayer_globals_table);

const mp_obj_module_t mp_module_trezormintlayer = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mp_module_trezormintlayer_globals,
};

MP_REGISTER_MODULE(MP_QSTR_trezormintlayer, mp_module_trezormintlayer);

// #endif  // MICROPY_PY_TREZORMINTLAYER

