import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, Routes } from '@angular/router';
import { UserDashboardComponent } from './user-dashboard.component';
import {MatToolbarModule } from '@angular/material/toolbar';
import {MatSidenavModule } from '@angular/material/sidenav';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import {MatListModule} from '@angular/material/list';
import { authGuard } from 'src/app/auth.guard';

// add more routes under user-dashborad
 const routes: Routes = [
   {
     path: '',
     component: UserDashboardComponent,
     children: [
       {
         path: '',
         redirectTo: 'assigned-tasks',
         pathMatch: 'full'
        },
        {
          path: 'assigned-tasks',
          loadChildren: () =>
            import('../../assigned-tasks/assigned-tasks.module')
              .then(m => m.AssignedTasksModule)
        },
        {
          path: 'create-task',
          loadChildren: () =>
            import('../../create-task/create-task.module')
              .then(m => m.CreateTaskModule),
              canActivate: [authGuard], data: { roles: ['Admin','Manager'] }
        },
        {
          path:'user-management',
          loadChildren: () =>
            import('../../user-management/user-management.module')
              .then(m => m.UserManagementModule),
              canActivate: [authGuard], data: { roles: ['Admin'] }
        },
        {
          path:'role-management',
          loadChildren: () =>
            import('../../role-management/role-management.module')
              .then(m => m.RoleManagementModule),
              canActivate: [authGuard], data: { roles: ['Admin'] }
        },
        
     ]
   }
];


@NgModule({
  declarations: [UserDashboardComponent], 
  imports: [
    CommonModule,
    MatToolbarModule,
    MatSidenavModule,
    MatIconModule,
    MatButtonModule,
    MatListModule,
    RouterModule.forChild(routes)
  ],
  exports: [RouterModule]
})

export class UserDashboardModule { }
