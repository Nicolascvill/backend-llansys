import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { ConfigService } from '@nestjs/config';
import { randomUUID } from 'crypto';

@Injectable()
export class AuthService {

    constructor(
        private usersService: UsersService,
        private jwtService: JwtService,
    ) { }

    async signup(email: string, password: string) {
        const userExists = await this.usersService.findByEmail(email);
        if (userExists) {
            throw new UnauthorizedException('Usuario ya registrado.');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const sessionId = randomUUID();
        const user = await this.usersService.create({ email, password: hashedPassword, sessionId });
        const payload = { sub: user.id, email: user.email, sid: sessionId };
        const accessToken = await this.jwtService.signAsync(payload, { expiresIn: '5m' });
        const refreshToken = await this.jwtService.signAsync(payload, { expiresIn: '7d' });
        await this.usersService.updateRefreshToken(user.id, refreshToken);
        return { accessToken, refreshToken };
    }

    async login(loginDto: LoginDto) {
        console.log("por lo menos llego aqui");
        const sessionId = randomUUID();
        const user = await this.usersService.findByEmail(loginDto.email);
        if (!user) throw new UnauthorizedException('Usuario o contraseña incorrectos.');
        const isPasswordValid = await bcrypt.compare(loginDto.password, user.password);
        if (!isPasswordValid) throw new UnauthorizedException('Usuario o contraseña incorrectos.');
        const payload = { sub: user.id, email: user.email, sid: sessionId };
        const accessToken = await this.jwtService.signAsync(payload, { expiresIn: '5m' });
        const refreshToken = await this.jwtService.signAsync(payload, { expiresIn: '7d' });
        await this.usersService.updateSessionId(user.id, sessionId);//guarda la nueva sesión
        await this.usersService.updateRefreshToken(user.id, refreshToken);
        return { accessToken, refreshToken };
    }

    async refresh(refreshToken: string) {
        const user = await this.usersService.findByRefreshToken(refreshToken);
        if (!user || user.refreshToken !== refreshToken) {
            throw new UnauthorizedException('Token inválido o sesión iniciada en otro dispositivo.');
        }
    
        // Incluir el SID actual del usuario
        const payload = { sub: user.id, email: user.email, sid: user.sessionId };
    
        console.log("***PAYLOAD****:",payload);
        const newAccessToken = await this.jwtService.signAsync(payload, { expiresIn: '15m' });
        return { accessToken: newAccessToken };
    }
    

    async logout(userId: number) {
        await this.usersService.removeRefreshToken(userId);
    }

}
