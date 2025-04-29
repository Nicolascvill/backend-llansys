import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(private usersService: UsersService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: 'SECRET_KEY', // mismo secret que en JwtModule.register
        });
    }

    async validate(payload: any) {
        console.log('🛡️ JwtStrategy.validate ejecutado. SID:', payload.sid);
    
        const user = await this.usersService.findById(payload.sub);
        if (!user) {
            console.warn('⚠️ Usuario no encontrado en la base de datos');
            throw new UnauthorizedException('Usuario no encontrado.');
        }
    
        if (user.sessionId !== payload.sid) {
            console.warn('🚫 SID inválido. Esperado:', user.sessionId, 'Recibido:', payload.sid);
            throw new UnauthorizedException('Sesión inválida o iniciada en otro dispositivo.');
        }
    
        console.log('✅ SID válido. Sesión continua.');
        return user;
    }
    

}
