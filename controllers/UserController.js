import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

import UserModel from '../models/User.js';
// регистрация пользователя
export const register = async (req, res) => {
  try {
    // оборачиваем весь код в try catch для отлова ошибок

    const password = req.body.password; // вытаскиваем password из бади
    const salt = await bcrypt.genSalt(10); //генерируем соль алгоритм шифрования
    const hash = await bcrypt.hash(password, salt); // тепреь passwordHash будет хранить зашифрованый пароль

    const doc = new UserModel({
      email: req.body.email,
      fullName: req.body.fullName,
      avatarUrl: req.body.avatarUrl,
      passwordHash: hash,
    });

    // создание пользователя в монгоДБ

    const user = await doc.save();

    const token = jwt.sign(
      {
        _id: user._id,
      },
      'secret123',
      {
        expiresIn: '30d',
      },
    );
    const { passwordHash, ...userData } = user._doc;

    res.json({
      ...userData,
      token,
    });
  } catch (err) {
    console.log(err); // ответ в консоль
    res.status(500).json({ message: 'не удалось зарегистрироваться' }); // ответ для пользователя
  }
};
// Авторизация
export const login = async (req, res) => {
  try {
    const user = await UserModel.findOne({ email: req.body.email }); // найти одного пользователя в базе с данной почтой

    if (!user) {
      // если такого пользователя нет вернуть ответ 404 пользователь не найден
      return res.status(404).json({
        message: 'Пользователь не найден',
      });
    }
    const isValidPass = await bcrypt.compare(req.body.password, user._doc.passwordHash); // проверяем совпадают ли пароли в теле запроса и в базе пассвордхэш

    if (!isValidPass) {
      return res.status(400).json({
        message: 'неверный логин или пароль',
      });
    }
    //если пользователь прошёл все проверки авторизовался создаём новый токен
    const token = jwt.sign(
      {
        _id: user._id,
      },
      'secret123',
      {
        expiresIn: '30d',
      },
    );
    const { passwordHash, ...userData } = user._doc;
    res.json({
      ...userData,
      token,
    });
  } catch (err) {
    console.log(err); // ответ в консоль
    res.status(500).json({ message: 'не удалось авторизоваться' }); // ответ для пользователя
  }
};
// check me
export const getMe = async (req, res) => {
  try {
    const user = await UserModel.findById(req.userId);
    if (!user) {
      return res.status(404).json({
        message: 'Пользователь не найден',
      });
    }
    const { passwordHash, ...userData } = user._doc;

    res.json(userData);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: 'нет доступа' });
  }
};
