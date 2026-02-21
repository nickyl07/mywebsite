<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'

const props = defineProps<{
  songs: Array<{ name: string, url: string }>
}>()

const isPlaying = ref(false)
const isHovered = ref(false)
const audioRef = ref<HTMLAudioElement | null>(null)
const currentSongIndex = ref(0)
const volume = ref(0.3) // 默认音量 50%
const isLock = ref(false)

const togglePlay = async () => {
  if (!audioRef.value || isLock.value) return
  isLock.value = true
  try {
    if (isPlaying.value) {
      audioRef.value.pause()
      isPlaying.value = false
    } else {
      await audioRef.value.play()
      isPlaying.value = true
    }
  } catch (e) {
    console.warn("自动播放受限:", e)
  } finally {
    isLock.value = false
  }
}

const nextSong = async () => {
  if (isLock.value) return
  isLock.value = true
  currentSongIndex.value = (currentSongIndex.value + 1) % props.songs.length
  
  setTimeout(async () => {
    try {
      if (audioRef.value) {
        audioRef.value.volume = volume.value
        await audioRef.value.play()
        isPlaying.value = true
      }
    } finally {
      isLock.value = false
    }
  }, 100)
}

const updateVolume = () => {
  if (audioRef.value) {
    audioRef.value.volume = volume.value
  }
}

onMounted(() => {
  if (props.songs.length > 0) {
    currentSongIndex.value = Math.floor(Math.random() * props.songs.length)
    const enableAudio = () => {
      togglePlay()
      window.removeEventListener('click', enableAudio)
    }
    window.addEventListener('click', enableAudio)
  }
})

const currentSong = computed(() => props.songs[currentSongIndex.value] || null)
</script>

<template>
  <div 
    class="fixed bottom-10 left-10 z-[100] transition-all duration-500 ease-in-out flex items-center bg-white/90 dark:bg-zinc-800/90 backdrop-blur-md border border-base shadow-lg overflow-hidden"
    :class="isHovered ? 'rounded-2xl px-4 py-2 max-w-[400px]' : 'rounded-full w-12 h-12 justify-center'"
    @mouseenter="isHovered = true"
    @mouseleave="isHovered = false"
  >
    <audio ref="audioRef" :src="currentSong?.url" @ended="nextSong" preload="auto"></audio>

    <div class="flex-shrink-0 flex items-center justify-center cursor-pointer transition-transform active:scale-90" @click="togglePlay">
      <div 
        class="i-ph-music-notes-fill text-xl text-black dark:text-white"
        :class="{ 'animate-pulse': isPlaying }"
      ></div>
    </div>

    <div v-if="isHovered" class="flex items-center ml-4 gap-4 overflow-hidden animate-fade-in animate-duration-300">
      <div class="flex flex-col min-w-0 flex-1">
        <span class="text-xs font-bold truncate max-w-30">{{ currentSong?.name }}</span>
        <input 
          type="range" 
          min="0" max="1" step="0.01" 
          v-model="volume" 
          @input="updateVolume"
          class="w-20 h-1 mt-1 accent-black dark:accent-white cursor-pointer"
        />
      </div>
      
      <div class="flex gap-3">
        <button @click.stop="nextSong" class="hover:text-orange-500 transition-colors">
          <div class="i-ph-skip-forward-fill text-lg text-black dark:text-white"></div>
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* 消除抖动：确保动画在中心旋转/缩放 */
.i-ph-music-notes-fill {
  display: block;
  transform-origin: center;
}

/* 简单的滑入动画 */
.animate-fade-in {
  animation: fadeIn 0.3s ease-out forwards;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateX(-10px); }
  to { opacity: 1; transform: translateX(0); }
}

/* 自定义滑动条样式 */
input[type='range'] {
  -webkit-appearance: none;
  background: rgba(0,0,0,0.1);
  border-radius: 2px;
}
input[type='range']::-webkit-slider-thumb {
  -webkit-appearance: none;
  height: 8px;
  width: 8px;
  border-radius: 50%;
  background: currentColor;
}
</style>