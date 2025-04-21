import { Injectable, UnauthorizedException } from '@nestjs/common';
import { SignInInput } from './dto/signin.input';
import { PrismaService } from 'src/prisma/prisma.service';
import { verify } from 'argon2';
import { User } from 'generated/prisma';
import { JwtService } from '@nestjs/jwt';
import { AuthJwtPayload } from './types/jwtPayload';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwtService: JwtService) {}

    async validateLocalUser({ email, password }: SignInInput): Promise<User> {
        const user = await this.prisma.user.findUnique({ where: { email } });

        if (!user) throw new UnauthorizedException('User not found');

        const passwordMatch = await verify(user.password, password);

        if (!passwordMatch) throw new UnauthorizedException('Invalid credentials');

        return user;

    }

    async generateToken(userId: number): Promise<string> {
        const payload: AuthJwtPayload = { sub: userId };
        const accessToken = await this.jwtService.signAsync(payload);
        return accessToken;
    }

    async login(user: User) {
        const accessToken = await this.generateToken(user.id);
        return {
            id: user.id,
            name: user.name,
            email: user.email,
            avatar: user.avatar,
            accessToken
        }
    }
}
