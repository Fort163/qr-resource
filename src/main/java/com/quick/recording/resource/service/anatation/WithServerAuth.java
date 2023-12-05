package com.quick.recording.resource.service.anatation;

import java.lang.annotation.*;

@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface WithServerAuth {
}
