package shop.mtcoding.blog._core.utils;

import org.junit.jupiter.api.Test;
import shop.mtcoding.blog.user.User;

public class JwtUtilTest {

    @Test
    public void created_test(){

        //given

        User user = User.builder()
                .id(1)
                .username("ssar")
                .build();

        //when
        String jwt = JwtUtil.create(user);
        System.out.println(jwt);
    }
}
