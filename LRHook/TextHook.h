#pragma once
#include <Windows.h>

void AttachTextFunctions();
void DetachTextFunctions();
void InitializeWindowTextFont(HWND window);
WPARAM WindowTextFont(HWND window, WPARAM requested);
