import { Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {

    constructor(private authService: AuthService){}
  @Post('/local/signup')
  signupLocal() {}

  @Post('/local/signin')
  signinLocal() {}

  @Post('/logout')
  logout() {}

  @Post('/refresh')
  refreshToken() {}
}
