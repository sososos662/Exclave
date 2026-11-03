/******************************************************************************
 *                                                                            *
 * Copyright (C) 2021 by nekohasekai <contact-sagernet@sekai.icu>             *
 *                                                                            *
 * This program is free software: you can redistribute it and/or modify       *
 * it under the terms of the GNU General Public License as published by       *
 * the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                       *
 *                                                                            *
 * This program is distributed in the hope that it will be useful,            *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 * GNU General Public License for more details.                               *
 *                                                                            *
 * You should have received a copy of the GNU General Public License          *
 * along with this program. If not, see <http://www.gnu.org/licenses/>.       *
 *                                                                            *
 ******************************************************************************/

package io.nekohasekai.sagernet.fmt;

import androidx.room.TypeConverter;

import com.esotericsoftware.kryo.KryoException;
import com.esotericsoftware.kryo.io.ByteBufferInput;
import com.esotericsoftware.kryo.io.ByteBufferOutput;

import java.io.ByteArrayOutputStream;

import io.nekohasekai.sagernet.database.SubscriptionBean;
import io.nekohasekai.sagernet.fmt.anytls.AnyTLSBean;
import io.nekohasekai.sagernet.fmt.http.HttpBean;
import io.nekohasekai.sagernet.fmt.http3.Http3Bean;
import io.nekohasekai.sagernet.fmt.hysteria2.Hysteria2Bean;
import io.nekohasekai.sagernet.fmt.internal.BalancerBean;
import io.nekohasekai.sagernet.fmt.internal.ChainBean;
import io.nekohasekai.sagernet.fmt.internal.ConfigBean;
import io.nekohasekai.sagernet.fmt.juicity.JuicityBean;
import io.nekohasekai.sagernet.fmt.masque.MASQUEBean;
import io.nekohasekai.sagernet.fmt.mieru.MieruBean;
import io.nekohasekai.sagernet.fmt.naive.NaiveBean;
import io.nekohasekai.sagernet.fmt.shadowquic.ShadowQUICBean;
import io.nekohasekai.sagernet.fmt.shadowsocks.ShadowsocksBean;
import io.nekohasekai.sagernet.fmt.shadowsocksr.ShadowsocksRBean;
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean;
import io.nekohasekai.sagernet.fmt.ssh.SSHBean;
import io.nekohasekai.sagernet.fmt.trojan.TrojanBean;
import io.nekohasekai.sagernet.fmt.trusttunnel.TrustTunnelBean;
import io.nekohasekai.sagernet.fmt.snell.SnellBean;
import io.nekohasekai.sagernet.fmt.tuic5.Tuic5Bean;
import io.nekohasekai.sagernet.fmt.v2ray.VLESSBean;
import io.nekohasekai.sagernet.fmt.v2ray.VMessBean;
import io.nekohasekai.sagernet.fmt.v2ray.StandardV2RayBean;
import io.nekohasekai.sagernet.fmt.wireguard.WireGuardBean;
import io.nekohasekai.sagernet.ktx.KryosKt;
import io.nekohasekai.sagernet.ktx.Logs;

public class KryoConverters {

    private static final byte[] NULL = new byte[0];

    @TypeConverter
    public static byte[] serialize(Serializable bean) {
        if (bean == null) return NULL;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteBufferOutput buffer = KryosKt.byteBuffer(out);
        bean.serializeToBuffer(buffer);
        buffer.flush();
        buffer.close();
        return out.toByteArray();
    }

    public static <T extends Serializable> T deserialize(T bean, byte[] bytes) {
        if (bytes == null) return bean;
        ByteBufferInput buffer = new ByteBufferInput(bytes);
        try {
            if (bean instanceof StandardV2RayBean profile) {
                try {
                    // Prefer our released v40 layout so existing installations upgrade intact.
                    profile.deserializeProfile(buffer, true);
                    if (!profile.matchesLegacyProfile(bytes, true)) {
                        throw new KryoException("Legacy WebSocket profile did not round trip");
                    }
                } catch (RuntimeException e) {
                    if (!profile.isLegacyWsProfile()) throw e;
                    // Upstream v40 has no frontingHost. Retry on a FRESH bean: a failed
                    // TLS/REALITY read must not leave stale fields in the imported profile.
                    T upstream = newBean(bean);
                    ((StandardV2RayBean) upstream).deserializeProfile(new ByteBufferInput(bytes), false);
                    if (!((StandardV2RayBean) upstream).matchesLegacyProfile(bytes, false)) {
                        throw new KryoException("Upstream WebSocket profile did not round trip");
                    }
                    bean = upstream;
                }
            } else {
                bean.deserializeFromBuffer(buffer);
            }
        } catch (KryoException e) {
            Logs.INSTANCE.w(e);
        }
        bean.initializeDefaultValues();
        return bean;
    }

    @SuppressWarnings("unchecked")
    private static <T extends Serializable> T newBean(T bean) {
        try {
            return (T) bean.getClass().getDeclaredConstructor().newInstance();
        } catch (ReflectiveOperationException e) {
            throw new KryoException("Cannot create profile for legacy format migration", e);
        }
    }

    @TypeConverter
    public static SOCKSBean socksDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new SOCKSBean(), bytes);
    }

    @TypeConverter
    public static HttpBean httpDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new HttpBean(), bytes);
    }

    @TypeConverter
    public static ShadowsocksBean shadowsocksDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new ShadowsocksBean(), bytes);
    }

    @TypeConverter
    public static ShadowsocksRBean shadowsocksRDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new ShadowsocksRBean(), bytes);
    }

    @TypeConverter
    public static VMessBean vmessDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new VMessBean(), bytes);
    }

    @TypeConverter
    public static VLESSBean vlessDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new VLESSBean(), bytes);
    }

    @TypeConverter
    public static TrojanBean trojanDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new TrojanBean(), bytes);
    }

    @TypeConverter
    public static NaiveBean naiveDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new NaiveBean(), bytes);
    }

    @TypeConverter
    public static Hysteria2Bean hysteria2Deserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new Hysteria2Bean(), bytes);
    }

    @TypeConverter
    public static SSHBean sshDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new SSHBean(), bytes);
    }

    @TypeConverter
    public static WireGuardBean wireguardDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new WireGuardBean(), bytes);
    }

    @TypeConverter
    public static MieruBean mieruDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new MieruBean(), bytes);
    }

    @TypeConverter
    public static Tuic5Bean tuic5Deserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new Tuic5Bean(), bytes);
    }

    @TypeConverter
    public static JuicityBean juicityDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new JuicityBean(), bytes);
    }

    @TypeConverter
    public static Http3Bean http3Deserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new Http3Bean(), bytes);
    }

    @TypeConverter
    public static AnyTLSBean anytlsDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new AnyTLSBean(), bytes);
    }

    @TypeConverter
    public static ShadowQUICBean shadowquicDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new ShadowQUICBean(), bytes);
    }

    @TypeConverter
    public static TrustTunnelBean trusttunnelDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new TrustTunnelBean(), bytes);
    }

    @TypeConverter
    public static SnellBean snellDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new SnellBean(), bytes);
    }

    @TypeConverter
    public static MASQUEBean masqueDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new MASQUEBean(), bytes);
    }

    @TypeConverter
    public static ConfigBean configDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new ConfigBean(), bytes);
    }

    @TypeConverter
    public static ChainBean chainDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new ChainBean(), bytes);
    }

    @TypeConverter
    public static BalancerBean balancerBeanDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new BalancerBean(), bytes);
    }

    @TypeConverter
    public static SubscriptionBean subscriptionDeserialize(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return null;
        return deserialize(new SubscriptionBean(), bytes);
    }

}
