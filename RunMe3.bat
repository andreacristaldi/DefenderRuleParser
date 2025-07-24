@echo off
setlocal

DefenderRuleParser.exe "output_mpasbase" --skip-existing
DefenderRuleParser.exe "output_mpavbase" --skip-existing
DefenderRuleParser.exe "output_mpasdlta" --skip-existing
DefenderRuleParser.exe "output_mpavdlta" --skip-existing


echo Operation completed.


endlocal





