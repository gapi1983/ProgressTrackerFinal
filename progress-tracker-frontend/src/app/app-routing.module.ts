import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { authGuard } from './auth.guard';


const routes: Routes = [
  // Public routes for login, register, etc.
  {
    path: 'login',
    loadChildren: () =>
      import('./login/login.module').then(m => m.LoginModule)
  },
  {
    path: 'register',
    loadChildren: () =>
      import('./register/register.module').then(m => m.RegisterModule)
  },
  {
    path:"user-dashboard",
    canActivate: [authGuard],
    loadChildren: () =>
    import('./dashboard/user-dashboard/user-dashboard.module').then(m => m.UserDashboardModule),
  },
  {
    path:"forgot-password",
    loadChildren: () =>
    import('./forgot-password/forgot-password.module').then(m => m.ForgotPasswordModule),
  },
  {
    path: 'confirm-email',
    loadChildren: () => import('./confirm-account/confirm-account.module')
      .then(m => m.ConfirmAccountModule)
  },
  {
    path:"reset-password",
    loadChildren: () =>
    import('./reset-password/reset-password.module').then(m => m.ReserPasswordModule),
  },
  {
    path:"setup-2fa",
    loadChildren: () =>
    import('./setup2fa/setup2fa.module').then(m => m.Setup2faModule),
  },
  {
    path: "",
    redirectTo: "login",
    pathMatch: "full" // Ensures full path matching for redirect
  },

];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
