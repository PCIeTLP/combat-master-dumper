#pragma once

#include <string>

void UiStart(const std::string& outDir, bool enabled);
void UiStage(const char* fmt, ...);
void UiLogLine(const char* text);
void UiDone(int rc);
void UiStop();
