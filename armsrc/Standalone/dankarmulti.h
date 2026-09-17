//-----------------------------------------------------------------------------
// Copyright (C) Daniel Karling, 2021
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// main code for Multi Loader
//-----------------------------------------------------------------------------
#ifndef _DANKARMULTI_H_
#define _DANKARMULTI_H_

#ifdef MODE_NAME
#error "Do not define MODE_NAME when including this first time"
#endif

#ifdef MODE_FILE
#error "Do not define MODE_FILE when including this first time"
#endif

#define STRINGIZE(X) STRINGIZE2(X)
#define STRINGIZE2(X) #X

#define CONCAT(X,Y) CONCAT2(X,Y)
#define CONCAT2(X, Y) X##Y

typedef void (*func_ptr)(void);

typedef struct mode_t {
    const char *name;
    func_ptr run;
    func_ptr info;
} mode_t;

#define MODE_INTERNAL_NAME(name) CONCAT(standalone_mode, CONCAT(_,name))
#define MODE_INFO_FUNC(name) CONCAT(ModInfo, CONCAT(_,name))
#define MODE_RUN_FUNC(name) CONCAT(RunMod, CONCAT(_,name))

#define START_MODE_LIST mode_t *mode_list[] = {
#define ADD_MODE(name) &MODE_INTERNAL_NAME(name),
#define END_MODE_LIST }; static const int NUM_MODES = ARRAYLEN(mode_list);

#else

#ifndef MODE_NAME
#error "Define LOAD_MODE before including this file multiple times"
#endif

#ifndef MODE_FILE
#error "Define LOAD_MODE before including this file multiple times"
#endif

void MODE_INFO_FUNC(MODE_NAME)(void);
void MODE_RUN_FUNC(MODE_NAME)(void);

#define ModInfo MODE_INFO_FUNC(MODE_NAME)
#define RunMod MODE_RUN_FUNC(MODE_NAME)

void ModInfo(void);
void RunMod(void);

#include MODE_FILE

static mode_t MODE_INTERNAL_NAME(MODE_NAME) = {
    .name = STRINGIZE(MODE_NAME),
    .run = RunMod,
    .info = ModInfo
};

#undef ModInfo
#undef RunMod
#undef MODE_FILE
#undef MODE_NAME

#endif
