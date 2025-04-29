import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class UsersService {
    constructor(
        @InjectRepository(User)
        private usersRepository: Repository<User>,
    ) { }

    async findByEmail(email: string): Promise<User | null> {
        return this.usersRepository.findOne({ where: { email } });
    }

    async create(userData: Partial<User>): Promise<User> {
        const user = this.usersRepository.create(userData);
        return this.usersRepository.save(user);
    }

    async updateRefreshToken(userId: number, refreshToken: string): Promise<void> {
        const user = await this.findById(userId);
        if (user?.refreshToken !== refreshToken) {
            await this.usersRepository.update(userId, { refreshToken });
        }
    }

    async removeRefreshToken(userId: number): Promise<void> {
        await this.usersRepository.update(userId, { refreshToken: '' });
    }

    async findById(id: number): Promise<User | null> {
        return this.usersRepository.findOne({ where: { id } });
    }

    async findByRefreshToken(refreshToken: string): Promise<User | null> {
        return this.usersRepository.findOne({ where: { refreshToken } });
    }

    async updateSessionId(userId: number, sessionId: string): Promise<void> {
        await this.usersRepository.update(userId, { sessionId })
    }
    
}
