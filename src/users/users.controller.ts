import { Controller, Get, UseGuards, Req } from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';

@Controller('users')
export class UsersController {

  @UseGuards(JwtAuthGuard)
  @Get('ping')
  checkSession(@Req() req) {
    console.log('📡 Endpoint /users/ping alcanzado. Headers:', req.headers);
    return { valid: true };
  }
}