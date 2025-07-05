const request = require('supertest');
const app = require('../server'); 

describe('Auth endpoints', () => {
  it('should return 401 for invalid login', async () => {
    const res = await request(app)
      .post('/login')
      .send({ username: 'fakeuser', password: 'wrongpass' });
    
    console.log(res.body, res.statusCode);
    expect(res.statusCode).toBe(401);
    expect(res.body.success).toBe(false);
  });
});