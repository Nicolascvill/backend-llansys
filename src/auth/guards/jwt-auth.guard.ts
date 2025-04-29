import { CanActivate,ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
    canActivate(context: ExecutionContext) {
        console.log('🛡️ JwtAuthGuard ejecutado');
        return super.canActivate(context);
      }
}