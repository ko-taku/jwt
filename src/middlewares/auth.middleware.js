const jwt = require('jsonwebtoken');
const { secretKey } = require('../config');

module.exports = {
  auth: (req, res, next) => {
    try {
      /*
        Todo: 요청 헤더에서 JWT를 추출하고, 토큰을 검증한 후
            verify하여 디코딩된 정보를 req.decoded에 저장합니다.
            이후 다음 프로세스를 위해 next()을 실행합니다.
      */

      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({ message: '토큰이 존재하지 않습니다.' });
      }
      const token = authHeader.startsWith('Bearer ')
        ? authHeader.split(' ')[1]
        : authHeader;
      const decoded = jwt.verify(token, secretKey);
      req.decoded = decoded;

      next();
    } catch (err) {
      /*
        Todo: err.name에 따라 조건에 맞는 응답을 반환합니다. 
          - TokenExpiredError : 419 응답코드와 함께 "토큰이 만료되었습니다."를 반환
          - JsonWebTokenError : 401 응답코드와 함께 "유효하지 않은 토큰입니다."를 반환
      */

      // - TokenExpiredError : 419 응답코드와 함께 "토큰이 만료되었습니다."를 반환
      if (err.name === 'TokenExpiredError') {
        return res.status(419).json({ message: '토큰이 만료되었습니다.' });
      }

      // - JsonWebTokenError : 401 응답코드와 함께 "유효하지 않은 토큰입니다."를 반환
      if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({ message: '유효하지 않은 토큰입니다.' });
      }
    }
  },
};