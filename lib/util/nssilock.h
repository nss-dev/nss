/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _NSSILOCK_H_
#define _NSSILOCK_H_
PR_BEGIN_EXTERN_C

#define PZ_NewLock(t) PR_NewLock()
#define PZ_DestroyLock(k) PR_DestroyLock((k))
#define PZ_Lock(k) PR_Lock((k))
#define PZ_Unlock(k) PR_Unlock((k))

#define PZ_NewCondVar(l) PR_NewCondVar((l))
#define PZ_DestroyCondVar(v) PR_DestroyCondVar((v))
#define PZ_WaitCondVar(v, t) PR_WaitCondVar((v), (t))
#define PZ_NotifyCondVar(v) PR_NotifyCondVar((v))
#define PZ_NotifyAllCondVar(v) PR_NotifyAllCondVar((v))

#define PZ_NewMonitor(t) PR_NewMonitor()
#define PZ_DestroyMonitor(m) PR_DestroyMonitor((m))
#define PZ_EnterMonitor(m) PR_EnterMonitor((m))
#define PZ_ExitMonitor(m) PR_ExitMonitor((m))
#define PZ_InMonitor(m) PR_InMonitor((m))
#define PZ_Wait(m, t) PR_Wait(((m)), ((t)))
#define PZ_Notify(m) PR_Notify((m))
#define PZ_NotifyAll(m) PR_Notify((m))
#define PZ_TraceFlush() /* nothing */

PR_END_EXTERN_C
#endif /* _NSSILOCK_H_ */
