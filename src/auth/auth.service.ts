import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {

    constructor(
        private usersService: UsersService,
        private jwtService: JwtService,    
    ) {}

    async signup(email: string, password: string) {
        const userExists = await this.usersService.findByEmail(email);
        if (userExists) {
            throw new UnauthorizedException('Usuario ya registrado.');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await this.usersService.create({ email, password: hashedPassword });
        const payload = { sub: user.id, email: user.email };
        const accessToken = await this.jwtService.signAsync(payload, { expiresIn: '15m' });
        const refreshToken = await this.jwtService.signAsync(payload, { expiresIn: '7d' });
        await this.usersService.updateRefreshToken(user.id, refreshToken);
        return { accessToken, refreshToken };
    }

    async login(loginDto:LoginDto) {
        const { email, password } = loginDto;
        const user = await this.usersService.findByEmail(email);
        if (!user) {
            throw new UnauthorizedException('Usuario o contraseña incorrectos.');
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            throw new UnauthorizedException('Usuario o contraseña incorrectos.');
        }
        const payload = { sub: user.id, email: user.email };
        const accessToken = await this.jwtService.signAsync(payload, { expiresIn: '15m' });
        const refreshToken = await this.jwtService.signAsync(payload, { expiresIn: '7d' });
        await this.usersService.updateRefreshToken(user.id, refreshToken);
        return { accessToken, refreshToken };
    }

    async refresh(refreshToken: string) {
        const user = await this.usersService.findByRefreshToken(refreshToken);
    
        if (!user) {
            throw new UnauthorizedException('Refresh token inválido.');
        }
    
        const payload = { sub: user.id, email: user.email };
        const newAccessToken = await this.jwtService.signAsync(payload, { expiresIn: '15m' });
    
        return { accessToken: newAccessToken };
    }

    async logout(userId: number) {
        await this.usersService.removeRefreshToken(userId);
    }

}
