import jwt from 'jsonwebtoken';

export default (req, res, next) => {
  const token = (req.headers.authorization || '').replace(/Bearer\s?/, ''); // если пришёл токен или ничего вырежи слово bearer и вместо него вставь пустую строку

  if (token) {
    try {
      const decoded = jwt.verify(token, 'secret123'); //расшифровываем токен

      req.userId = decoded._id;
      next();
    } catch (e) {
      return res.status(403).json({
        message: 'нет доступа',
      });
    }
  } else {
    return res.status(403).json({
      message: 'нет доступа',
    });
  }
};
