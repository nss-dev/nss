/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _NSSILOCK_H_
#define _NSSILOCK_H_
PR_BEGIN_EXTERN_C

#define PZ_NewLock(t) MPR_NewLock()
#define PZ_DestroyLock(k) MPR_DestroyLock((k))
#define PZ_Lock(k) MPR_Lock((k))
#define PZ_Unlock(k) MPR_Unlock((k))

#define PZ_NewCondVar(l) MPR_NewCondVar((l))
#define PZ_DestroyCondVar(v) MPR_DestroyCondVar((v))
#define PZ_WaitCondVar(v, t) MPR_WaitCondVar((v), (t))
#define PZ_NotifyCondVar(v) MPR_NotifyCondVar((v))
#define PZ_NotifyAllCondVar(v) MPR_NotifyAllCondVar((v))

#define PZ_NewMonitor(t) MPR_NewMonitor()
#define PZ_DestroyMonitor(m) MPR_DestroyMonitor((m))
#define PZ_EnterMonitor(m) MPR_EnterMonitor((m))
#define PZ_ExitMonitor(m) MPR_ExitMonitor((m))
#define PZ_InMonitor(m) PR_InMonitor((m))
#define PZ_Wait(m, t) MPR_Wait(((m)), ((t)))
#define PZ_Notify(m) MPR_Notify((m))
#define PZ_NotifyAll(m) MPR_Notify((m))
#define PZ_TraceFlush() /* nothing */

PR_END_EXTERN_C
#endif /* _NSSILOCK_H_ */
