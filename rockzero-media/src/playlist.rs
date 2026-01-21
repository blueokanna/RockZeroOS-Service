pub struct PlaylistGenerator {
    session_id: String,
    base_url: String,
}

impl PlaylistGenerator {
    pub fn new(session_id: String, base_url: String) -> Self {
        Self {
            session_id,
            base_url,
        }
    }

    pub fn generate_master_playlist(&self, qualities: &[(&str, u32)]) -> String {
        let mut playlist = String::from("#EXTM3U\n");
        playlist.push_str("#EXT-X-VERSION:3\n\n");

        for (quality, bandwidth) in qualities {
            playlist.push_str(&format!(
                "#EXT-X-STREAM-INF:BANDWIDTH={},RESOLUTION={}\n",
                bandwidth, quality
            ));
            playlist.push_str(&format!(
                "{}/api/v1/hls/{}/playlist_{}.m3u8\n\n",
                self.base_url, self.session_id, quality
            ));
        }

        playlist
    }

    pub fn generate_media_playlist(
        &self,
        segment_count: usize,
        segment_duration: f32,
        use_encryption: bool,
    ) -> String {
        let mut playlist = String::from("#EXTM3U\n");
        playlist.push_str("#EXT-X-VERSION:3\n");
        playlist.push_str(&format!(
            "#EXT-X-TARGETDURATION:{}\n",
            segment_duration.ceil() as u32
        ));
        playlist.push_str("#EXT-X-MEDIA-SEQUENCE:0\n");
        if use_encryption {
            playlist.push_str(&format!(
                "#EXT-X-KEY:METHOD=AES-256,URI=\"{}/api/v1/hls/{}/key\"\n",
                self.base_url, self.session_id
            ));
        }

        playlist.push('\n');

        for i in 0..segment_count {
            playlist.push_str(&format!("#EXTINF:{:.3},\n", segment_duration));
            playlist.push_str(&format!(
                "{}/api/v1/hls/{}/segment_{}.ts\n",
                self.base_url, self.session_id, i
            ));
        }

        playlist.push_str("#EXT-X-ENDLIST\n");
        playlist
    }

    pub fn generate_encrypted_playlist_multi_key(
        &self,
        segment_count: usize,
        segment_duration: f32,
    ) -> String {
        let mut playlist = String::from("#EXTM3U\n");
        playlist.push_str("#EXT-X-VERSION:3\n");
        playlist.push_str(&format!(
            "#EXT-X-TARGETDURATION:{}\n",
            segment_duration.ceil() as u32
        ));
        playlist.push_str("#EXT-X-MEDIA-SEQUENCE:0\n\n");

        // 每个分片使用不同的密钥
        for i in 0..segment_count {
            playlist.push_str(&format!(
                "#EXT-X-KEY:METHOD=AES-256,URI=\"{}/api/v1/hls/{}/key/{}\"\n",
                self.base_url, self.session_id, i
            ));
            playlist.push_str(&format!("#EXTINF:{:.3},\n", segment_duration));
            playlist.push_str(&format!(
                "{}/api/v1/hls/{}/segment_{}.ts\n",
                self.base_url, self.session_id, i
            ));
        }

        playlist.push_str("#EXT-X-ENDLIST\n");
        playlist
    }

    /// 生成实时流播放列表（不包含 ENDLIST）
    pub fn generate_live_playlist(
        &self,
        segment_count: usize,
        segment_duration: f32,
        sequence_number: u64,
    ) -> String {
        let mut playlist = String::from("#EXTM3U\n");
        playlist.push_str("#EXT-X-VERSION:3\n");
        playlist.push_str(&format!(
            "#EXT-X-TARGETDURATION:{}\n",
            segment_duration.ceil() as u32
        ));
        playlist.push_str(&format!("#EXT-X-MEDIA-SEQUENCE:{}\n", sequence_number));

        // 加密密钥
        playlist.push_str(&format!(
            "#EXT-X-KEY:METHOD=AES-256,URI=\"{}/api/v1/hls/{}/key\"\n\n",
            self.base_url, self.session_id
        ));

        // 添加分片
        for i in 0..segment_count {
            let segment_num = sequence_number + i as u64;
            playlist.push_str(&format!("#EXTINF:{:.3},\n", segment_duration));
            playlist.push_str(&format!(
                "{}/api/v1/hls/{}/segment_{}.ts\n",
                self.base_url, self.session_id, segment_num
            ));
        }

        playlist
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_playlist() {
        let generator = PlaylistGenerator::new(
            "test-session-123".to_string(),
            "http://localhost:8080".to_string(),
        );

        let qualities = vec![
            ("1920x1080", 5000000),
            ("1280x720", 2500000),
            ("854x480", 1000000),
        ];

        let playlist = generator.generate_master_playlist(&qualities);

        assert!(playlist.contains("#EXTM3U"));
        assert!(playlist.contains("1920x1080"));
        assert!(playlist.contains("BANDWIDTH=5000000"));
    }

    #[test]
    fn test_media_playlist() {
        let generator = PlaylistGenerator::new(
            "test-session-456".to_string(),
            "http://localhost:8080".to_string(),
        );

        let playlist = generator.generate_media_playlist(5, 10.0, true);

        assert!(playlist.contains("#EXTM3U"));
        assert!(playlist.contains("#EXT-X-KEY"));
        assert!(playlist.contains("segment_0.ts"));
        assert!(playlist.contains("segment_4.ts"));
        assert!(playlist.contains("#EXT-X-ENDLIST"));
    }

    #[test]
    fn test_live_playlist() {
        let generator = PlaylistGenerator::new(
            "live-session".to_string(),
            "http://localhost:8080".to_string(),
        );

        let playlist = generator.generate_live_playlist(3, 6.0, 100);

        assert!(playlist.contains("#EXT-X-MEDIA-SEQUENCE:100"));
        assert!(playlist.contains("segment_100.ts"));
        assert!(!playlist.contains("#EXT-X-ENDLIST"));
    }
}
