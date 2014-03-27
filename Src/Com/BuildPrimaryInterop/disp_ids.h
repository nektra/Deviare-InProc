/*
 * Copyright (C) 2010-2014 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved.
 *
 **/

typedef [v1_enum] enum eNktDispIds {
  dispidNktHookLibHook = 1,
  dispidNktHookLibRemoteHook,
  dispidNktHookLibUnhook,
  dispidNktHookLibUnhookProcess,
  dispidNktHookLibUnhookAll,
  dispidNktHookLibEnableHook,
  dispidNktHookLibSuspendThreadsWhileHooking,
  dispidNktHookLibShowDebugOutput,
  dispidNktHookLibRemoveHook,
  dispidNktHookLibGetModuleBaseAddress,
  dispidNktHookLibGetRemoteModuleBaseAddress,
  dispidNktHookLibGetProcedureAddress,
  dispidNktHookLibGetRemoteProcedureAddress,
  //----
  dispidNktHookInfoId = 1,
  dispidNktHookInfoOrigProcAddr,
  dispidNktHookInfoNewProcAddr,
  dispidNktHookInfoCallOriginal
} eNktDispIds;
