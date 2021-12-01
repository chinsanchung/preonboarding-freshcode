## 프리온보딩 백엔드 과정 2번째 과제: 프레시코드

[프레시코드](https://www.freshcode.me/)에서 제공해주신 API 설계 과제입니다. 헤로쿠를 이용해 배포했으며, 주소는 [https://pocky-freshcode-subject.herokuapp.com](https://pocky-freshcode-subject.herokuapp.com)입니다.

## 과제에 대한 안내

1. 로그인 기능

사용자 인증을 통해 상품을 관리할 수 있어야 합니다.

- JWT 인증 방식을 이용합니다.
- 서비스 실행시 데이터베이스 또는 In Memory 상에 유저를 미리 등록해주세요.
- Request시 Header에 Authorization 키를 체크합니다.
- Authorization 키의 값이 없거나 인증 실패시 적절한 Error Handling을 해주세요.
- 상품 추가/수정/삭제는 admin 권한을 가진 사용자만 이용할 수 있습니다.
- 사용자 인증 / 인가

2. 상품 관리 기능

아래 상품 JSON 구조를 이용하여 데이터베이스 및 API를 개발해주세요.

- 서비스 실행시 데이터베이스 또는 In Memory 상에 상품 최소한 5개를 미리 생성해주세요.
- 상품 조회는 하나 또는 전체목록을 조회할 수 있으며, 전체목록은 페이징 기능이 있습니다.
  - 한 페이지 당 아이템 수는 5개 입니다.
- 사용자는 상품 조회만 가능합니다.
- 관리자는 상품 추가/수정/삭제를 할 수 있습니다.
- 상품 관리 API 개발시 적절한 Error Handling을 해주세요.

## 데이터베이스 ERD

![프레시코드 데이터베이스 ERD](https://user-images.githubusercontent.com/33484830/140525485-889dcef7-e006-458c-b56e-0fb605f29d27.PNG)

## 개발 환경

- 언어: TypeScript
- 데이터베이스: SQLite3
- 사용 도구: NestJs, typeorm, passport, passport-local, passport-jwt, bcrypt, class-validator

## API 문서

포스트맨으로 작성한 [API 문서](https://documenter.getpostman.com/view/15323948/UVC2HpCf)에서 상세한 내용을 확인하실 수 있습니다.

## 실행 방법

1. `git clone` 으로 프로젝트를 가져온 후, `npm install` 으로 필요한 패키지를 설치합니다.
2. 루트 디렉토리에 .env 파일을 생성하고, 임의의 문자열 값을 가진 `JWT_SECRET`을 작성합니다.
3. 개발 환경일 때는`npm run start:dev`으로, 배포 환경일 때는 `npm run build`으로 빌드한 후 `npm run start:prod`을 입력하시면 로컬에서 테스트하실 수 있습니다.

## 수행한 작업

### 유저 생성

입력한 이메일으로 동일한 유저가 존재하는지를 확인한 후, 존재하면 에러 상태 코드를 응답으로 보내고, 존재하지 않으면 유저를 생성합니다.

```typescript
export class UsersService {
  async createUser({ email, password, role }: CreateUserDto): Promise<{
    ok: boolean;
    htmlStatus?: number;
    error?: string;
  }> {
    try {
      // 1. email check
      const existUser = await this.usersRepository.findOne({ email });
      if (existUser) {
        return {
          ok: false,
          htmlStatus: 409,
          error: '이미 가입한 이메일입니다.',
        };
      }
      await this.usersRepository.save(
        this.usersRepository.create({ email, password, role })
      );
      return { ok: true };
    } catch (error) {
      return {
        ok: false,
        htmlStatus: 500,
        error: '유저 생성에 에러가 발생했습니다.',
      };
    }
  }
}
```

```typescript
export class UsersController {
  @Post()
  async createUser(@Body() createBody: CreateUserDto) {
    const result = await this.usersService.createUser(createBody);
    if (result.ok) {
      return {
        message: '회원가입에 성공하였습니다.',
      };
    } else {
      throw new HttpException(result.error, result.htmlStatus);
    }
  }
}
```

### 로그인, 로그인 인증 및 로그아웃

#### 로그인

[passport-local](https://www.npmjs.com/package//passport-local)으로 로컬 전략을, [@nestjs/passport](https://www.npmjs.com/package/@nestjs/passport)으로 `LocalAuthGuard` 를 만들어서 로그인 메소드에 대입해 로그인을 수행합니다.

```typescript
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'email',
      passwordField: 'password',
    });
  }

  async validate(email, password) {
    const loginUserDto = { email, password };
    const result = await this.authService.validateUser(loginUserDto);
    if (result.ok) {
      return {
        email: result.data.email,
        role: result.data.role,
        loginedAt: result.data.loginedAt,
      };
    } else {
      throw new HttpException(result.error, result.htmlStatus);
    }
  }
}
```

```typescript
export class AuthService {
  async validateUser({ email, password }: LoginUserDto) {
    try {
      const user = await this.usersService.findOne(email);
      if (!user || (user && !(await bcrypt.compare(password, user.password)))) {
        return {
          ok: false,
          htmlStatus: 403,
          error: '올바르지 않은 이메일 또는 비밀번호 입니다.',
        };
      }
      const loginedAt = new Date();
      await this.usersService.updateLoginedAt(email, loginedAt);
      return {
        ok: true,
        data: { email: user.email, role: user.role, loginedAt },
      };
    } catch (error) {
      return {
        ok: false,
        htmlStatus: 500,
        error: '로그인 과정에서 에러가 발생했습니다.',
      };
    }
  }
}
```

마지막으로 `@UseGuards(LocalAuthGuard)`로 로컬 전략의 로그인 과정을 통과하고 나면, authServie 의 로그인 메소드로 토큰을 발급해 리턴합니다. 토큰 발급은 [@nestjs/jwt](https://www.npmjs.com/package/@nestjs/jwt)의 `JwtService` 를 이용해 jsonwebtoken 으로 발급합니다.

```typescript
export class AuthController {
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req) {
    return this.authService.login(req.user);
  }
}
```

```typescript
import { JwtService } from '@nestjs/jwt';

export class AuthService {
  constructor(private jwtService: JwtService) {}
  async login(user) {
    const payload = { user };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
```

jsonwebtoken 을 발급할 때 어떻게 발급할 것인지 설정을 추가할 수 있는데, [auth.module.ts](https://github.com/chinsanchung/preonboarding-freshcode/blob/master/src/auth/auth.module.ts)의 `JwtModule`에서 할 수 있습니다.

```typescript
@Module({
  imports: [
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secretOrPrivateKey: configService.get('JWT_SECRET'),
        signOptions: { expiresIn: '1h' },
      }),
      inject: [ConfigService],
    }),
  ],
})
export class AuthModule {}
```

`registerAsync()`을 사용한 이유는 `useFactory`를 통해 비동기로 .env 파일에서 키를 가져오기 위해서입니다. [@nestjs/config](https://www.npmjs.com/package/@nestjs/config)의 `ConfigModule`, `ConfigService`으로 .env 의 값을 가져올 수 있습니다. 그리고 `expiresIn`을 "1h"로 함으로써 1시간 후에 토큰이 만료되도록 설정했습니다.

#### 로그인 인증 및 데코레이터

상품을 관리하는 API 는 jsonwebtoken 으로 발급한 토큰을 Header 의 Bearer Token 에 넣은 후에 요청을 보내도록 되어있습니다. 이 토큰을 `JwtAuthGuard`를 통해 토큰을 검증 및 해석하고, `JwtStrategy`의 `validate` 메소드에서 토큰의 내용이 유효한지를 다시 검증한 후에 Request body 에 추가합니다.

```typescript
export class JwtStrategy extends PassportStrategy(Strategy) {
  async validate(payload: any) {
    const { email, role, loginedAt } = payload.user;
    const user = await this.usersService.findOne(email);
    const tokenLoginedAt = new Date(loginedAt).getTime();
    const userLoginedAt = new Date(user.loginedAt).getTime();
    if (tokenLoginedAt !== userLoginedAt) {
      throw new UnauthorizedException('올바르지 않은 토큰입니다');
    }
    return { email, role, loginedAt };
  }
}
```

`validate`메소드로 추가한 유저 정보를 `req.user`로 가져오는 대신, 다른 팀원의 조언에 따라 `GetUser` 데코레이터로 가져오는 방법을 택했습니다. 다만, GraphQL 으로 구현한 API 였다면 `ExecutionContext`의 내용을 http 에서 GraphQL 형식으로 교체하는 목적으로 이 데코레이터를 사용했을텐데, REST API 로 작성한 이번 프로젝트에서는 `req.user`로 가져오는 것이 더 간편하지 않을지 생각합니다.

```typescript
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const GetUser = createParamDecorator((_, ctx: ExecutionContext) => {
  const req = ctx.switchToHttp().getRequest();
  const user = {
    email: req.user.email,
    role: req.user.role,
    loginedAt: req.user.loginedAt,
  };
  return user;
});
```

#### 로그아웃

마지막으로 로그아웃입니다. 로그아웃을 구현하기 위해, 유저 테이블에서 loginedAt 컬럼을, 토큰에도 loginedAt 을 넣어 두 값을 비교하여 로그아웃 여부를 확인하는 방법을 택했습니다. 한 번 발급한 jwt 토큰은 지정한 시간에 만료되기 전까지는 언제나 유효해 그것을 만료시킬 방법 중 떠올린 것이 이 방법이었습니다.

위의 `JwtStrategy`의 `validate` 메소드를 다시 살펴보면, 토큰에 저장한 tokenLoginedAt 과 유저 데이터에 담긴 userLoginedAt 을 비교하여 일치하지 않으면 로그아웃한 유저의 토큰으로 인식하는 것이 목적이었습니다.

```typescript
const tokenLoginedAt = new Date(loginedAt).getTime();
const userLoginedAt = new Date(user.loginedAt).getTime();

if (tokenLoginedAt !== userLoginedAt) {
  throw new UnauthorizedException('올바르지 않은 토큰입니다');
}
```

이 방법으로 시간이 만료되지 않은 토큰이라도 로그아웃 기능을 수행해 만료된 토큰으로 만들 수 있었습니다.

## 폴더 구조

```
|   .eslintrc.js
|   .gitignore
|   .prettierrc
|   freshcode
|   nest-cli.json
|   package-lock.json
|   package.json
|   Procfile
|   README.md
|   tsconfig.build.json
|   tsconfig.json
|
+---src
|   |   app.controller.ts
|   |   app.module.ts
|   |   app.service.ts
|   |   main.ts
|   |
|   +---auth
|   |   |   auth.controller.ts
|   |   |   auth.module.ts
|   |   |   auth.service.spec.ts
|   |   |   auth.service.ts
|   |   |   get-user.decorator.ts
|   |   |
|   |   +---auth-guard
|   |   |       jwt-auth.guard.ts
|   |   |       local-auth.guard.ts
|   |   |
|   |   +---dto
|   |   |       login-user.dto.ts
|   |   |
|   |   \---strategies
|   |           jwt.strategy.ts
|   |           local.strategy.ts
|   |
|   +---categories
|   |   |   categories.controller.ts
|   |   |   categories.module.ts
|   |   |   categories.repository.ts
|   |   |   categories.service.ts
|   |   |
|   |   +---dto
|   |   |       create-update-category.dto.ts
|   |   |
|   |   \---entities
|   |           category.entity.ts
|   |
|   +---core
|   |   \---entities
|   |           core.entity.ts
|   |
|   +---items
|   |   |   items.controller.spec.ts
|   |   |   items.controller.ts
|   |   |   items.module.ts
|   |   |   items.repository.ts
|   |   |   items.service.spec.ts
|   |   |   items.service.ts
|   |   |
|   |   +---dto
|   |   |       create-item.dto.ts
|   |   |       update-item.dto.ts
|   |   |
|   |   \---entities
|   |           item.entity.ts
|   |
|   +---menus
|   |   |   menus.controller.ts
|   |   |   menus.module.ts
|   |   |   menus.repository.ts
|   |   |   menus.service.spec.ts
|   |   |   menus.service.ts
|   |   |
|   |   +---dto
|   |   |       create-menu.dto.ts
|   |   |       relation-menu-tag.dto.ts
|   |   |       update-menu.dto.ts
|   |   |
|   |   \---entities
|   |           menu.entity.ts
|   |
|   +---tags
|   |   |   tags.controller.ts
|   |   |   tags.module.ts
|   |   |   tags.repository.ts
|   |   |   tags.service.ts
|   |   |
|   |   +---dto
|   |   |       create-tag.dto.ts
|   |   |       select-tag.dto.ts
|   |   |       update-tag.dto.ts
|   |   |
|   |   \---entities
|   |           tag.entity.ts
|   |
|   \---users
|       |   users.controller.spec.ts
|       |   users.controller.ts
|       |   users.module.ts
|       |   users.service.spec.ts
|       |   users.service.ts
|       |
|       +---dto
|       |       create-user.dto.ts
|       |
|       \---entities
|               user.entity.ts
|
\---test
        app.e2e-spec.ts
        jest-e2e.json
```
