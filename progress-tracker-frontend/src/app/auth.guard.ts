import { CanActivateFn, Router, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { inject } from '@angular/core';
import { AccountService } from './account.service';
import { map, of, switchMap } from 'rxjs';

export const authGuard: CanActivateFn = (route: ActivatedRouteSnapshot, state: RouterStateSnapshot) => {
  const accountService = inject(AccountService);
  const router = inject(Router);

  return accountService.checkAuthStatus().pipe(
    switchMap(isLogged => {
      if (!isLogged) {
        router.navigate(['/login']);
        return of(false);
      }
      const requiredRoles = route.data['roles'] as string[] || [];
      if (requiredRoles.length === 0) {
        return of(true);
      }

      const userRoles = accountService.currentUser?.roles || [];
      const hasRequiredRole = requiredRoles.some(role => userRoles.includes(role));
      if (!hasRequiredRole) {

        router.navigate(['/user-dashboard']);
        return of(false);
      }
      return of(true);
    })
  );
};
