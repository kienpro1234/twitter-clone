import { MediaType } from '~/constants/enum'

export interface Media {
  url: string
  type: MediaType // 0: image, 1: video
}
