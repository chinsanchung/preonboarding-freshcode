import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Category } from 'src/categories/entities/category.entity';
import { CreateMenuDto } from './dto/create-menu.dto';
import { UpdateMenuDto } from './dto/update-menu.dto';
import { Menu } from './entities/menu.entity';
import { MenusRepository } from './menus.repository';

@Injectable()
export class MenusService {
  constructor(
    @InjectRepository(MenusRepository)
    private menusRepository: MenusRepository,
  ) {}

  async getMenus(): Promise<Menu[]> {
    return await this.menusRepository.find();
  }

  async getMenuById(id: number): Promise<Menu> {
    const menu = await this.menusRepository.findOne({ id });
    if (!menu) {
      throw new NotFoundException('유효한 메뉴 id가 아닙니다.');
    }
    return menu;
  }

  createMenu(createMenuDto: CreateMenuDto, category: Category): Promise<Menu> {
    return this.menusRepository.createMenu(createMenuDto, category);
  }

  async updateMenu(id: number, updateMenuDto: UpdateMenuDto): Promise<Menu> {
    if (Object.keys(updateMenuDto).length === 0) {
      throw new BadRequestException('요청 수정 값이 잘못되었습니다.');
    }
    await this.menusRepository.update({ id }, updateMenuDto);
    return await this.getMenuById(id);
  }
}
