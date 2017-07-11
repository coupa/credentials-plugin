/*
 * The MIT License
 *
 * Copyright (c) 2011-2012, CloudBees, Inc., Stephen Connolly.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.cloudbees.plugins.credentials.matchers;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsMatcher;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import org.apache.commons.lang.StringEscapeUtils;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
/**
 * Matches all of the supplied matchers.
 *
 * @since 1.5
 */
public class IdPrefixMatcher implements CredentialsMatcher, CredentialsMatcher.CQL {
    /**
     * Standardize serialization.
     *
     * @since 2.1.0
     */
    @NonNull
    private final Pattern regex_pattern;

    /**
     * Constructs a new instance.
     *
     * @param regex_pattern the pattern to match 
     */
    public IdPrefixMatcher(@NonNull String regex_pattern) { 
        this.regex_pattern = Pattern.compile(regex_pattern);
    }

    /**
     * {@inheritDoc}
     */
    public boolean matches(@NonNull Credentials item) {
        Matcher m = regex_pattern.matcher(((IdCredentials) item).getId());
        return item instanceof IdCredentials && m.matches();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String describe() {
        return regex_pattern.toString();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return regex_pattern.hashCode();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        IdPrefixMatcher that = (IdPrefixMatcher) o;

        return regex_pattern.equals(that.regex_pattern);

    }

     /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("IdPrefixMatcher{");
        sb.append("regex_pattern='").append(regex_pattern).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
